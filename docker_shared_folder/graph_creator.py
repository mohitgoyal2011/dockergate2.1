import sys,os
import subprocess
import logging
import json
import graphviz as gv

#Function to search through all executables and bash scripts in the docker container. Function to modify if you want to change the way the graph is being traversed
'''
At this time, the Depth First Search is being done by the following logic
1. If it is a bash or sh file, it is marked as a red node. "which" is performed on each word. For each of the words with a proper output (example: echo would point ot /bin/echo),
   , a new "blue" node is created.
2. DFS is then performed on this blue node. For all the libraries it is connected to are marked as white nodes. That is done by using ldd.
Both python and ldd are packaged as statically linked files here
'''
def dfs_search(binary, call_graph, binary_set, executable):
    binary_set.add(binary)
    if executable:
        if binary.endswith('.sh'):
            call_graph.node(binary, binary, color = 'red')
            logging.info('Adding ' + binary + ' as red' )
            f = open(binary,'r')
            for line in f.readlines():
                if line.startswith('#'):
                    continue
                words = line.split(' ')
                for word in words:
                    if not word.startswith('/') and not  word.isalnum():
                        continue
                    if os.path.isfile(word):
                        logging.info('Now here - ' + binary + ':' + word)
                        if word not in binary_set:
                            logging.info('Now adding - ' + binary + ':' + word)
                            dfs_search(word, call_graph, binary_set, True)
                        call_graph.edge(binary,word)
                    else:
                        logging.info("which " + word)
                        try:
                            output = subprocess.check_output("which " +  word, shell=True, universal_newlines=True)
                        except:
                            logging.info(word + ' not an executable')
                            continue
                        output = str(output).strip()
                        logging.info('Output: ' + str(output))
                        if os.path.isfile(str(output)):
                            logging.info('It is a file:' + str(output))
                            if output not in binary_set:
                                logging.info('Performing DFS on ' + str(output))
                                dfs_search(output, call_graph, binary_set, True)
                            call_graph.edge(binary,str(output))
            return
        else:
            call_graph.node(binary, binary, color = 'blue')
            logging.info('Adding ' + binary + ' as blue' )
    else:
        call_graph.node(binary, binary, color = 'white')
        logging.info('Adding ' + binary + ' as white' )
    complete_path = os.path.realpath(binary)
    try:
        ldd_output = subprocess.check_output('ldd ' + complete_path, shell=True, universal_newlines=True).split('\n')
    except Exception as e:
        logging.error('This sounds statically linked ' + str(e) )
        return   
    linked_libraries_list = []
    for lib in ldd_output:
        try:
            lib = lib.split("=>")[1].split('(')[0].strip()
        except:
            lib =  lib.split(" ")[0].strip()
        if os.path.islink(lib):
            realpath = os.readlink(lib)
            lib = os.path.dirname(lib) + '/' + realpath
            if not os.path.exists(lib):
                lib = '/' + realpath
        if not os.path.exists(lib) or not os.path.isfile(lib):
            continue
        if lib not in binary_set:
            dfs_search(lib, call_graph, binary_set, False)
        call_graph.edge(binary, lib)
    return
FORMAT = '%(asctime)-15s %(funcName)s %(levelname)s : %(message)s'
logging.basicConfig(filename='/docker_shared_folder/output.log',level=logging.DEBUG, format=FORMAT)
rootDir = '/'
call_graph = gv.Digraph(format='dot')
binary_set = set()
for dirName, subdirList, filelist in os.walk(rootDir):
    for fname in filelist:
        if 'test_code' in dirName:
            continue
        filename = dirName + '/' + fname
        if os.path.isfile(filename) and os.access(filename, os.X_OK):
            if filename not in binary_set:
                dfs_search(filename, call_graph, binary_set, True)
f= open('/docker_shared_folder/test.dot','w')
f.write(call_graph.source)
