#!/bin/bash
# RUN FROM SERVER LOCATION

echo "-------------------------------- Performing tests --------------------------------"

# Variables
project_path_client="/home/ak/encrypted_covert_channel/cmake-build-debug"
repeat_number=20
ip_address=10.10.1.5

echo "Path $project_path_client"
cd $project_path_client

# covert channel types: storage IP_id HTTP LSB sequence loss timing
# cipher types: aes des present rsa clefia grain

for covert_channel_type in sequence
do
  cct=$covert_channel_type
  for cipher_type in rsa 
  do
    echo "Testing covert channel type : $covert_channel_type ; cipher: $cipher_type"
    sudo ./encrypted_covert_channel --server $cct --is_encrypted $cipher_type &
    sleep 5
    for i in $(seq 1 1 $repeat_number)
    do
      echo "Repeat number $i"
      echo "sudo ./encrypted_covert_channel --client  $cct --is_encrypted $cipher_type " | nc -w 5 $ip_address 5000
      echo "Raz dwa trzy"
      sleep 4
    done
    sleep 10
    echo "Killing server"
    sudo pkill -f encrypted_covert_channel
    sleep 2
    sudo pkill -f encrypted_covert_channel
    echo "sudo pkill -f encrypted_covert_channel" | nc -w 5 $ip_address 5000
  done
done

echo ""
echo "-------------------------------- Tests finished --------------------------------"
