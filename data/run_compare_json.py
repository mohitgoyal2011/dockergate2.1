import os
import sys

for f in os.listdir('.'):
    if ".json" in f:
        os.system('python compare_json.py ' + f + ' ubuntu.json')
