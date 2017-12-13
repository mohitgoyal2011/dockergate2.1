import json
import sys,os
import subprocess

image_name = sys.argv[1]
policy = {}
policy["defaultAction"] = "SCMP_ACT_ERRNO"
policy["syscalls"] = []
f = open(os.getenv('DOCKERGATE_HOME') + '/temp_policy/' + image_name.replace('/','_') + '_tmp.json', 'r')
syscalls = json.loads(f.readlines()[0])
f.close()
syscalls.append('capget')
syscalls.append('capset')
syscalls.append('chdir')
syscalls.append('futex')
syscalls.append('fchown')
syscalls.append('readdirent')
syscalls.append('getdents64')
syscalls.append('getpid')
syscalls.append('getppid')
syscalls.append('lstat')
syscalls.append('openat')
syscalls.append('prctl')
syscalls.append('setgid')
syscalls.append('setgroups')
syscalls.append('setuid')
syscalls.append('stat')
syscalls.append('rt_sigreturn')
for syscall in syscalls:
    s = {}
    try:
        if str(syscall).isdigit():
            if int(syscall)>=0:
                s['name'] = subprocess.check_output('ausyscall ' + str(syscall),shell=True).strip()
            else:
                continue
        else:
            s['name'] = syscall
        s["action"] = "SCMP_ACT_ALLOW"
        s["args"] = []
        policy["syscalls"].append(s)
    except Exception as e:
        print str(e)

policyjson = open(os.getenv('DOCKERGATE_HOME') + '/data/' + image_name.replace('/','_') + '.json', 'w')
policyjson.write(json.dumps(policy))
policyjson.close()

if len(policy["syscalls"])<=17:
    os.rename("data/" + image_name.replace('/','_') + '.json', "data/failed_policy/" + image_name.replace('/','_') + '.json')
    os.rename("data/log/" + image_name.replace('/','_') + '.log', "data/failed_log/"   + image_name.replace('/','_') + '.log')    
