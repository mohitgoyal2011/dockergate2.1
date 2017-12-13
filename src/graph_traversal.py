import sys,os
import subprocess
import logging
from lib_analysis import ELFAnalysis
import json
import networkx as nx
lib_dict = {}

def analyze_file(binary, executable, linked_libraries_list):
    global lib_dict
    logging.info('******************************************************************************************************************************')
    logging.info("Now beginning to analyze :" + binary)
    analysis_obj = ELFAnalysis(image_name)
    new_list = classify(binary, analysis_obj, executable, image_name, linked_libraries_list)
    if not executable:
        return None
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

def classify(binary, analysis_obj, executable, image_name, linked_libraries_list):
    global lib_dict
    logging.info('Now analyzing ' + binary)
    basename = binary.split('/')[-1]
    try:
        subprocess.call('docker cp ' + image_name + '_dockergate_container:' + binary + ' snapshot', shell=True)
        hash_value = subprocess.check_output('/usr/bin/rahash2 -qa sha256 snapshot/' + basename, shell=True).split(' ')[0]
    except Exception as e:
        logging.error('Error in docker copying ' + str(e))
        return None
    lib_dict[binary] = hash_value
    linked_hash_list = []
    for l in linked_libraries_list:
        try:
            linked_hash_list.append(lib_dict[l])
        except Exception as e:
            logging.error('Error in reading linked_hash_list:' + str(e))
    if not executable:
        if not analysis_obj.check_for_library(hash_value):
            analysis_obj.analyze_library(binary, linked_hash_list)
        else:
            logging.info('Already found ' + binary + ' in database')
    else: #This should always be the first call
        syscall_list = analysis_obj.analyze_executable(binary, linked_hash_list)
        return syscall_list
    return None

def graph_traversal(image_name):
    try:
        filename = 'graphs/' + image_name + '.dot'
        graph = nx.DiGraph(nx.nx_pydot.read_dot(filename))
        for n in graph.nodes.keys():
            if graph.nodes[n]['color'] == 'blue':
                dfs_post_order = list(nx.dfs_postorder_nodes(graph,n))
                for f in dfs_post_order:
                    linked_lib_list = list(nx.dfs_postorder_nodes(graph,f))[:-1]
                    analyze_file(f, f == dfs_post_order[-1], linked_lib_list)
    except Exception as e:
        logging.error('Error in graph traversal ' + str(e))

image_name = sys.argv[1].replace('/','_')
FORMAT = '%(asctime)-15s %(funcName)s %(levelname)s : %(message)s'
logging.basicConfig(filename=os.getenv('DOCKERGATE_HOME') + '/data/log/' + image_name + '.log',level=logging.DEBUG, format=FORMAT)    
graph_traversal(image_name)
