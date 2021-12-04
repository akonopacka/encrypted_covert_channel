#!/bin/bash
# RUN FROM SERVER LOCATION

echo "-------------------------------- Performing tests --------------------------------"

# Variables
project_path_client="/home/ak/encrypted_covert_channel/cmake-build-debug"
repeat_number=1
ip_address=0.0.0.0

echo "Path $project_path_client"
cd $project_path_client

# covert channel types: timing storage IP_id HTTP LSB sequence loss
# cipher types: aes des present rsa clefia grain

for covert_channel_type in  timing
do
  cct=$covert_channel_type
  echo "Testing covert channel type : $cct "
  #  Test without encryption
  echo "Server starting for $cct"
#  pwd
#  sudo ./encrypted_covert_channel --server $cct &
#  sleep 5
#  for i in $(seq 1 1 $repeat_number)
#  do
#    echo "Repeat number $i"
#    echo "sudo ./encrypted_covert_channel --client  $cct" | nc $ip_address 5000
#    echo "Raz dwa trzy"
#    sleep 2
#  done
#  sleep 20
#  sudo pkill -f encrypted_covert_channel
#  sleep 2

  for cipher_type in aes des present rsa clefia grain
  do
    echo "Testing covert channel type : $covert_channel_type ; cipher: $cipher_type"
    sudo ./encrypted_covert_channel --server $cct --is_encrypted $cipher_type &
    sleep 2
    for i in $(seq 1 1 $repeat_number)
    do
       echo ""
       echo "./encrypted_covert_channel --client  $cct --is_encrypted $cipher_type " | nc  $ip_address 5000
       echo "Raz dwa trzy"
     sleep 2
    done
    sleep 20
    sudo pkill -f encrypted_covert_channel
    sleep 2
    sudo pkill -f encrypted_covert_channel
  done
done

echo ""
echo "-------------------------------- Tests finished --------------------------------"
