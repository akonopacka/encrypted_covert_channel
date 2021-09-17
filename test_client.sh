#!/bin/bash

echo "-------------------------------- Performing tests --------------------------------"

# Variables
project_path="/home/ak/encrypted_covert_channel/cmake-build-debug"
repeat_number=5

echo "Path $project_path"
cd $project_path


for i in $(seq 1 1 $repeat_number)
do
   echo ""
   ./encrypted_covert_channel --client loss --is_encrypted des
   sleep 2
done

echo "-------------------------------- Tests finished --------------------------------"