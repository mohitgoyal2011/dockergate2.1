import sys,os
import subprocess
import logging
from lib_analysis import ELFAnalysis
import json

def classify(binary, analysis_obj, executable, image_name):
    current_home = os.getenv('DOCKERGATE_HOME') + '/snapshot/' + image_name + '_snapshot'
    complete_path = os.path.realpath(binary)
    if current_home not in complete_path:
	    complete_path = current_home + complete_path
    print complete_path
    try:
        ldd_output = subprocess.check_output('ldd ' + complete_path, shell=True).split('\n')
    except:
        logging.error('This sounds statically linked')
        return []
    linked_libraries_list = []

    #First will check whether all dependent libraries are already in the database. For this, we will have to recursively call this function till we get a library or a statically linked library
    for lib in ldd_output:
        try:
            lib = current_home + lib.split("=>")[1].split('(')[0].strip()
        except:
            lib = current_home + lib.split(" ")[0].strip()
        if os.path.islink(lib):
            realpath = os.readlink(lib)
            lib = os.path.dirname(lib) + '/' + realpath
            logging.info('Getting the real file :' + lib)
            if not os.path.exists(lib):
                lib = current_home + '/' + realpath
        if not os.path.exists(lib) or not os.path.isfile(lib):
            logging.error('Could not find :' + lib)
            continue
        logging.info('Now analyzing ' + lib)
        hash_value = subprocess.check_output('/usr/bin/rahash2 -qa sha256 ' + lib, shell=True).split(' ')[0]
        if not analysis_obj.check_for_library(hash_value):
            classify(lib,analysis_obj, False, image_name)
        else:
            logging.info('Already found ' + lib + ' in database')
        linked_libraries_list.append(hash_value)
    if not executable:
        analysis_obj.analyze_library(binary,linked_libraries_list)
    else: #This should always be the first call
        syscall_list = analysis_obj.analyze_executable(binary, linked_libraries_list)
        return syscall_list
    
    return None
    
image_name = sys.argv[2].replace('/','_')
FORMAT = '%(asctime)-15s %(funcName)s %(levelname)s : %(message)s'
logging.basicConfig(filename=os.getenv('DOCKERGATE_HOME') + '/data/log/' + image_name + '.log',level=logging.DEBUG, format=FORMAT)    

logging.info('******************************************************************************************************************************')
logging.info("Now beginning to analyze :" + sys.argv[1])
analysis_obj = ELFAnalysis(image_name)
new_list = classify(sys.argv[1], analysis_obj, True, image_name)
try:
    new_list.remove(-1)
    new_list.remove(4294967284)
except Exception as e:
    logging.info('Scanned for -1')
try:
    tmp_json_file = os.getenv('DOCKERGATE_HOME') + '/temp_policy/' + image_name + '_tmp.json'
    f = open(tmp_json_file,'r')
    current_policy = f.readlines()[0]
    f.close()
    syscall_set = set(json.loads(current_policy))
    syscall_set.update(new_list)
    f = open(tmp_json_file,'w')
    f.write(json.dumps(list(syscall_set)))
    f.close()

except Exception as e:
    logging.error(str(e))

logging.info('******************************************************************************************************************************')
