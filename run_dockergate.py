import multiprocessing
from multiprocessing import Pool
import subprocess
import time
import Queue
import logging
import os

if __name__ == '__main__':
    f = open('community-docker-2000.txt','r').readlines()
    for name in f[41:80]:
        name = name.strip()
        if os.path.exists('data/' + name.replace('/','_') + '.json'):
            continue
        cmd = './dockergate_test_start.sh '+ name
        e = open('index.txt','a')
        try:
            subprocess.call(cmd, shell=True)
        except Exception as g:
            e.write(name + ': ERROR ' + str(g) + '\n')
            continue
        e.write(name + ':OK\n')
        e.close()
        
