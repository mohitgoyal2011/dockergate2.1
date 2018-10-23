import os
import sys
import subprocess

out = open('test_output2.txt','w')
for f in os.listdir('data'):
    if f.endswith('.json'):
        img_name = f.replace('_','/',1).split('.json')[0]
        print 'Testing ' + img_name
        try:
            p = subprocess.check_output("docker run -d --name=test_mohit --security-opt seccomp=data/" + f + " " + img_name, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e :
            out.write('\n' + img_name + ':' + str(e))
            print str(e)
        try:           
            o = subprocess.check_output('docker ps --filter="name=test_mohit" --format "{{.Status}}"', shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e :
            out.write('\n' + img_name + ':' + str(e))
            print str(e)
        try:
            n = subprocess.check_output('docker stop test_mohit',shell=True)
        except subprocess.CalledProcessError as e :
            out.write('\n' + img_name + ':' + str(e))
            print str(e)
        try:
            n = subprocess.check_output('docker rm test_mohit',shell=True)
        except subprocess.CalledProcessError as e :
            out.write('\n' + img_name + ':' + str(e))
            print str(e)
        out.write('\n' + img_name + ':' + str(p) + ':' + o)
        out.write('***************************************************')
        #p.stdout.readlines()
        print 'Finished Testing ' + img_name
out.close()
