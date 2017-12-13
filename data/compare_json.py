import json
import os,sys
import subprocess

for f in os.listdir('.'):
    if '.json' in f:
        #print f
        try:
            a = json.loads(open(f,'r').readlines()[0])
            b = json.loads(open(f,'r').readlines()[0])
        except Exception as e:
            continue
        counta = 0
        countb = 0
        counta = len(a['syscalls'])
        for c in b['syscalls']:
            flag = False
            countb = countb+1
            for d in a['syscalls']:
                if d['name'] == c['name']:
                    flag = True
                    break
            if not flag:
                #print c['name']
                continue

    #if counta<=17:
    #     os.rename(sys.argv[1], "failed_policy/" + sys.argv[1])
    #    os.rename("log/" + sys.argv[1].replace(".json",".log"), "failed_log/" + sys.argv[1].replace(".json",".log"))

    #    print f + ':' + str(counta)
        print f + ':' + str(countb)
