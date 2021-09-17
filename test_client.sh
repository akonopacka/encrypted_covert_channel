#!/bin/bash

echo "-------------------------------- Performing tests --------------------------------"

# shellcheck disable=SC1066
project_path="/home/ak/encrypted_covert_channel/cmake-build-debug"
echo "Path $project_path"
cd $project_path
./encrypted_covert_channel --client loss --is_encrypted des

echo "-------------------------------- Tests finished --------------------------------"