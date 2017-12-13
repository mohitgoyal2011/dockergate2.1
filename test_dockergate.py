import os
import sys
import subprocess

out = open('test_output.txt','w')
for f in os.listdir('data'):
    if f.endswith('.json'):
        img_name = f.replace('_','/',1).split('.json')[0]
        print 'Testing ' + img_name
        p = subprocess.Popen(["docker run -v ~/dockergate2.0/framework_test:/test --security-opt seccomp=data/" + f + " -it " + img_name + " sh /test/test_docker.sh"],shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE )
        while p.poll() is None:
            l = p.stdout.readline() # This blocks until it receives a newline.
            if "Operation" in l:
                p.kill()
                out.write("\nFailure:" + img_name + ':' +  l)
                break
            if 'NAME' in l or 'DESCRIPTION' in l:
                out.write("\n " + img_name + ":" + l.strip())
        out.write('\n' + img_name + ':' + str(p.returncode))
        out.write('***************************************************')
        #p.stdout.readlines()
        print 'Finished Testing ' + img_name
out.close()
