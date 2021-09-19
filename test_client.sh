#!/bin/bash

echo "-------------------------------- Performing tests --------------------------------"

# Variables
project_path="/home/ak/encrypted_covert_channel/cmake-build-debug"
repeat_number=5
covert_channel_method=loss
cipher_method=des
ip_address=127.0.0.1

echo "Path $project_path"
cd $project_path

printf "cd encrypted_covert_channel/cmake-build-debug; ./encrypted_covert_channel --server  loss --is_encrypted des \n" | nc  0.0.0.0 5000 &
#./encrypted_covert_channel --server $covert_channel_method --is_encrypted $cipher_method

for covert_channel_type in timing storage IP_id HTTP LSB sequence loss
do
  for cipher_type in aes des present rsa clefia grain
  do
    echo "Testing covert channel type : $covert_channel_type ; cipher: $cipher_type"
  done
done

for i in $(seq 1 1 $repeat_number)
do
   echo ""
   ./encrypted_covert_channel --client $covert_channel_method --is_encrypted $cipher_method
   sleep 2
done

echo "-------------------------------- Tests finished --------------------------------"
