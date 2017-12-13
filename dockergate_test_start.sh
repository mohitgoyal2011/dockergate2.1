#!/bin/bash
#Declaring variables
export DOCKERGATE_HOME=$PWD
mkdir snapshot/
imagename=$(echo "$1" | tr / _)
echo ${imagename}
echo '[]' > $DOCKERGATE_HOME/temp_policy/${imagename}_tmp.json
#Reading Dockergate Image into Snapshot folder
docker run -v $PWD/test_code:/test_code --name ${imagename}_dockergate_container -it  $1 /test_code/python-static /test_code/graph_creator.py
docker stop ${imagename}_dockergate_container
mv test_code/test.dot graphs/${imagename}.dot
mv test_code/output.log data/log/${imagename}.log
python src/graph_traversal.py ${imagename}
python src/dockergate_write_policy.py ${imagename}
docker rm ${imagename}_dockergate_container
rm -rf snapshot/*
