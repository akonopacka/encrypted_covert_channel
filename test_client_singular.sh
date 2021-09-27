#!/bin/bash

echo "-------------------------------- Performing tests --------------------------------"

# Variables
project_path="/home/ak/encrypted_covert_channel/cmake-build-debug"
repeat_number=20
ip_address=0.0.0.0

echo "Path $project_path"
cd $project_path

#printf "cd encrypted_covert_channel/cmake-build-debug; ./encrypted_covert_channel --server  loss --is_encrypted des \n" | nc  0.0.0.0 5000 &
#./encrypted_covert_channel --server $covert_channel_method --is_encrypted $cipher_method
#timing storage IP_id HTTP LSB sequence loss
# aes des present rsa clefia grain
#./encrypted_covert_channel --server loss --is_encrypted present

for i in $(seq 1 1 $repeat_number)
do
  echo "$i"
  sudo ./encrypted_covert_channel --client loss --is_encrypted present
  sleep 2
done


echo ""
echo "-------------------------------- Tests finished --------------------------------"
