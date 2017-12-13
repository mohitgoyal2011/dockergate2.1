#!/bin/bash
#Declaring variables
export DOCKERGATE_HOME=$PWD
imagename=$(echo "$1" | tr / _)
echo ${imagename}
echo '[]' > $DOCKERGATE_HOME/temp_policy/${imagename}_tmp.json
#Reading Dockergate Image into Snapshot folder
docker run --name ${imagename}_dockergate_container -d $1
docker export ${imagename}_dockergate_container > ${imagename}_snapshot.tar
docker stop ${imagename}_dockergate_container
docker rm ${imagename}_dockergate_container



#Mounting the snapshot folder
#rm -rf snapshot/
mkdir snapshot/${imagename}_snapshot/
mv ${imagename}_snapshot.tar snapshot/${imagename}_snapshot/
cd snapshot/${imagename}_snapshot/
tar -xf ${imagename}_snapshot.tar

#First analyzing all libraries and their export symbols
#FILES=$(find . -exec file {} \; | grep -i elf | cut -d ':' -f1)
FILES=$(find . -exec file {} \;| cut -d ':' -f1)
for f in  $FILES
do
    if [[ -x "$f" ]]
    then
	    echo $f
	    python ../../src/classifier.py $DOCKERGATE_HOME/snapshot/${imagename}_snapshot/$f ${imagename}
    fi
done
cd $DOCKERGATE_HOME

python src/dockergate_write_policy.py ${imagename}

rm -rf snapshot/${imagename}_snapshot/
rm $DOCKERGATE_HOME/temp_policy/${imagename}_tmp.json
