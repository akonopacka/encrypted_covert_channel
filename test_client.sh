#!/bin/bash

echo "-------------------------------- Performing tests --------------------------------"

# Variables
project_path="/home/ak/encrypted_covert_channel/cmake-build-debug"
repeat_number=1
ip_address=0.0.0.0

echo "Path $project_path"
cd $project_path

#printf "cd encrypted_covert_channel/cmake-build-debug; ./encrypted_covert_channel --server  loss --is_encrypted des \n" | nc  0.0.0.0 5000 &
#./encrypted_covert_channel --server $covert_channel_method --is_encrypted $cipher_method
#timing storage IP_id HTTP LSB sequence loss
# aes des present rsa clefia grain
for covert_channel_type in  storage IP_id HTTP LSB sequence loss timing
do
  cct=$covert_channel_type
  echo "Testing covert channel type : $cct "
  #  Test without encryption
  echo "sudo ./encrypted_covert_channel --server  $cct" | nc $ip_address 5000 &
  sleep 5
  echo "Server starting for $cct"
  #	echo "echo "./encrypted_covert_channel --server  $cct \n" | nc  0.0.0.0 5000 &"
  #	echo "./encrypted_covert_channel --client $cct"
  for i in $(seq 1 1 $repeat_number)
  do
    echo "Repeat number $i"
    sudo ./encrypted_covert_channel --client $cct
    sleep 2
  done
  sleep 10
  echo "sudo pkill -f encrypted_covert_channel" | nc  $ip_address 5000 &
  echo "sudo pkill -f encrypted_covert_channel" | nc  $ip_address 5000 &
  sleep 2

	for cipher_type in aes des present rsa clefia grain
	do
		echo "Testing covert channel type : $covert_channel_type ; cipher: $cipher_type"
		echo "./encrypted_covert_channel --server  $cct --is_encrypted $cipher_type " | nc  $ip_address 5000 &
		sleep 2
		echo "./encrypted_covert_channel --client $cct --is_encrypted"
		for i in $(seq 1 1 $repeat_number)
		do
			 echo ""
			 sudo ./encrypted_covert_channel --client $cct --is_encrypted $cipher_type
		 sleep 2
	  done
    sleep 5
    echo "sudo pkill -f encrypted_covert_channel" | nc  $ip_address 5000 &
    echo "sudo pkill -f encrypted_covert_channel" | nc  $ip_address 5000 &
    sleep 2
	done
done

echo ""
echo "-------------------------------- Tests finished --------------------------------"
