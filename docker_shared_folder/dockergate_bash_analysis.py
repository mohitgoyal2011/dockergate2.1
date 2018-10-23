import os,sys
import subprocess

f = open(sys.argv[1],'r')
for line in f.readlines():
	if line.startswith("#"):
		continue
	words = line.split(' ')
	for word in words:
		output = subprocess.call("which " + word, shell=True)
		print "Mohit" + output
