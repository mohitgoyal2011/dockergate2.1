import r2pipe
import sys,os
import pymysql
import sqlite3 as db
import json
import subprocess
import logging

hash_value = None
lib_name = None

class ELFAnalysis:
        def __init__(self,image_name):
            database_file = os.getenv('DOCKERGATE_HOME') + '/data/database/dockergate.db'
            self.conn = db.connect(database_file)
            self.r2p = None
            self.lib_list = []
            self.image_name = image_name
            
        def insert_syscalls_into_libraries(self, syscalls, function):
            global hash_value, lib_name
            cur = self.conn.cursor()
            cmd  ="INSERT into libraries values('%s','%s','%s','%s')" %(lib_name, hash_value, function, syscalls)
            cur.execute(cmd)
            self.conn.commit()
            logging.info(cmd)
        
        def insert_syscalls_into_binaries(self, syscalls, binary, hash_value):
            cur = self.conn.cursor()
            binary = binary.split(os.getenv('DOCKERGATE_HOME') + '/snapshot/' + self.image_name + '_snapshot')[-1].strip()
            cmd  ="INSERT into binaries values('%s','%s','%s')" %(binary, hash_value, syscalls)
            cur.execute(cmd)
            self.conn.commit()
            logging.info(cmd)

        def get_syscalls(self,function):
            global hash_value
            try:
                cur = self.conn.cursor()
                cmd = "SELECT syscalls from libraries where ("
                for l in self.lib_list:
                    cmd = cmd + "hash = '" + l + "' "
                    if l != self.lib_list[-1]:
                        cmd = cmd + 'or '
                    else:
                        cmd = cmd + ' ) and'
                cmd = cmd + " (function = '%s' or function = '__%s') order by length(syscalls) desc" %(function, function)
                logging.debug(cmd)
                cur.execute(cmd)
                syscalls = cur.fetchmany(size = 1)
                if len(syscalls)>0:
                    return json.loads(str(syscalls[0][0]))
                else:
                    return []
            except Exception as e:
                logging.error(e)
                return None

        def check_for_library(self,hash_value):
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT distinct(name) from libraries where hash='%s'" %(hash_value))
                result = cur.fetchmany(size = 1)
                if len(result)>0:
                    return True
                else:
                    return False
            except Exception as e:
                logging.error(e)
                return False
        
        def check_for_binary(self,hash_value):
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT distinct(name) from binaries where hash='%s'" %(hash_value))
                result = cur.fetchmany(size = 1)
                if len(result)>0:
                    return True
                else:
                    return False
            except Exception as e:
                logging.error('Something wrong with querying the database for binaries ' + str(e)) 
                return False
        
        def get_syscalls_from_binaries(self,hash_value):
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT syscalls from binaries where hash='%s'" %(hash_value))
                syscalls = cur.fetchmany(size = 1)
                if len(syscalls)>0:
                    return json.loads(str(syscalls[0][0]))
                else:
                    return []
            except Exception as e:
                logging.error('Something wrong with querying the database for binaries ' + str(e))
                return []

        def follow_eax(self,l,start,reg):
            for i in range(0,start+1)[::-1]:
                    if 'mov' in l[i] and reg in l[i]:
                            components = [x.strip(',') for x in l[i].split(' ')]
                            if reg!=components[1]:
                                continue
                            syscall = components[2]
                            if '[' in syscall or 'word' in syscall:
                                return -1                
                            if not syscall == None and (syscall.isdigit() or syscall.startswith('0x')):
                                    if not syscall.isdigit():
                                        n = syscall.split('0x')[1]
                                    else:
                                        n = syscall
                                    num = int(n,16)
                                    return num
                            else:
                                    return self.follow_eax(l,i-1,syscall)
            return -1 


        def get_syscalls_for_function(self, a,import_list, total_func_list, first_time):	
            #Checking all system calls only
            if 'seen' in a.keys():   #This code will have no effect. TODO
                #get system calls from database
                syscalls = self.get_syscalls(a['name'])
                print(a['name'] + ' :Already in database')
                return syscalls
            a['seen'] = True
            ret_list = []
            key = 'name'
            logging.debug('Processing ' + a[key])
            funcs =json.loads(self.r2p.cmd('pdrj@'+str(a[key])))
            try:
                funcs = [x['opcode'] for x in funcs if 'opcode' in x.keys() and ('mov' in x['opcode'] or 'syscall' in x['opcode'])]
            except Exception as e:
                logging.error(lib_name + ' ' + str(e))
                return []
            for i in range(0,len(funcs)):
                if 'syscall' in funcs[i]:
                    try:
                        syscall_num = self.follow_eax(funcs,i-1,'eax')
                    except Exception as e:
                        logging.error(e)
                        syscall_num = -1
                    logging.debug('Syscall = ' + str(syscall_num))
                    if syscall_num!=-1 or syscall_num<340:
                        ret_list.append(syscall_num)
            funcs = json.loads(self.r2p.cmd('agcj '+str(a[key])))
            if len(funcs)>0:
                funcs = funcs[0]['imports']
            logging.debug('Imports:' + str(funcs))
            for f in funcs:
                f = f.split('.')[-1]
                if f in import_list:
                    logging.debug('Requires System calls from ' + f)
                    #get system calls from database
                    syscalls = self.get_syscalls(f)
                    ret_list.extend(syscalls)
                else:
                    #recursively go into this function to get its own system calls
                    for b in total_func_list:
                        if b['name'].split('.')[-1] == f and b['name']!=a[key]:
                            try:
                                if 'seen' not in b.keys():
                                    print b['name']
                                    ret_list.extend(self.get_syscalls_for_function(b, import_list, total_func_list, False))
                                    b['seen'] = True
                                else:
                                    #get system calls from database
                                    syscalls = self.get_syscalls(f)
                                    ret_list.extend(syscalls)
                            except Exception as e:
                                logging.error('It was probably quitting here ' + b['name'] + ' ' + str(e))
            #Insert System calls into MySQL database 
            try:
                self.insert_syscalls_into_libraries(str(list(set(ret_list))), a[key].split('.')[-1])
            except Exception as e:
                logging.error("Exception while inserting syscalls for : "  + a[key].split('.')[-1] + ' ' + str(e))
            return ret_list


        #When this code is invoked - it is with the assurance that all dependencies for this library have been met.
        def analyze_library(self, lib, lib_linked_list):
            global conn, hash_value, lib_name
            self.lib_list = lib_linked_list
            print lib_linked_list
            basename = lib.split('/')[-1]
            filename = os.getenv('DOCKERGATE_HOME') + '/snapshot/' + basename
            self.r2p=r2pipe.open(filename)  # open without arguments only for #!pipe
            hash_value = subprocess.check_output('/usr/bin/rahash2 -qa sha256 ' + filename, shell=True).split(' ')[0]
            self.lib_list.append(hash_value)
            print 'Now analyzing ' +  lib
            lib_name = lib
            logging.info('Now analyzing ' + lib_name)
            print(hash_value,lib_name)
            self.r2p.cmd('aaa')  # analyze all symbols and calls

            #export_list =self.r2p.cmdj('iEj')
            import_list =self.r2p.cmdj('iij')
            total_func_list =self.r2p.cmdj('aflj')
            count = 0
            for a in total_func_list:
                if 'sym.imp' not in a['name']:
                    print('[+] Function '+a['name']) 
                    logging.info('[+] Function '+a['name'])
                    count = count + 1
                    try:
                        ret_list = self.get_syscalls_for_function(a, import_list, total_func_list, True)
                    except Exception as e:
                        logging.error('Couldnot analyze ' + a['name'] + ':' + str(e))
            logging.info('Finished analyzing ' + lib + ' Analyzed ' + str(count) + ' export functions')
            self.r2p.cmd('exit')

        def analyze_executable(self, binary, lib_linked_list):
            self.lib_list = lib_linked_list
            filename = os.getenv('DOCKERGATE_HOME') + '/snapshot/' + binary.split('/')[-1]
            print 'analyzing ' + binary
            rabin2_output = subprocess.check_output("rabin2 -ij " + filename, shell=True)
            logging.debug('Now analyzing ' + binary)
            ret_list = set()
            try:
                hash_value = subprocess.check_output('/usr/bin/rahash2 -qa sha256 ' + filename, shell=True).split(' ')[0]
                if self.check_for_binary(hash_value):
                    logging.info("Binary already found !")
                    return self.get_syscalls_from_binaries(hash_value)
                imported_symbols = json.loads(rabin2_output)
                for symbol in imported_symbols['imports']:
                    if symbol['type'] == 'FUNC':
                        logging.debug('Getting '+ symbol['name'] + ' for ' + binary)
                        ret_list.update(self.get_syscalls(symbol['name']))
                self.insert_syscalls_into_binaries((str(list(ret_list))), binary, hash_value)
                return list(ret_list)
            except Exception  as e:
                logging.error('Something is wrong with analysis of ' + binary + ' ' + str(e))
                return []
             
            

                        

