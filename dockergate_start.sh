#!/bin/bash

#TO START DOCKERGATE, RUN THIS FILE WITH THE IMAGE NAME AS THE ARGUMENT FROM THE MAIN FOLDER ITSELF

#Pre-Run
#Declaring variables
export DOCKERGATE_HOME=$PWD

#creating folder to store snapshot
mkdir snapshot/

#Replacing all / with _ as ' it messes up the folder structure. We can have a better way here but this is minor
imagename=$(echo "$1" | tr / _)
echo ${imagename}

#Initializing a temporary json file with zero system calls
echo '[]' > $DOCKERGATE_HOME/temp_policy/${imagename}_tmp.json

#Reading Dockergate Image into Snapshot folder and then creating a graph. This part is phase 1. The code within docker_shared_folder is run within the docker container. One issue is that this analsis also includes the code within this folder whereas it is supposed to ignore it
docker run -v $PWD/docker_shared_folder:/docker_shared_folder --name ${imagename}_dockergate_container -it  $1 /docker_shared_folder/python-static /docker_shared_folder/graph_creator.py
docker stop ${imagename}_dockergate_container

#Starting phase 2 with graph traversal on the dot file created. Open graph_traversal.py to modify how it is traversing the graph. Then based on the graph traversal output, the policy is written.
mv docker_shared_folder/test.dot graphs/${imagename}.dot
mv docker_shared_folder/output.log data/log/${imagename}.log
python src/graph_traversal.py ${imagename}
python src/dockergate_write_policy.py ${imagename}
docker rm ${imagename}_dockergate_container
rm -rf snapshot/*

#END
