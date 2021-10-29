#!/bin/bash

echo "-------------------------------- Performing tests --------------------------------"

# Variables
project_path="/home/ak/encrypted_covert_channel/cmake-build-debug"
# covert channel types: timing storage IP_id HTTP LSB sequence loss
# cipher types: aes des present rsa clefia grain
cct=loss
cipher_type=clefia

echo "Path $project_path"
cd $project_path

topp() (
  $* &>/dev/null &
  pid="$!"
  trap ':' INT
  echo 'CPU  MEM'
  while 
  sleep 0.1; do ps --no-headers -o '%cpu,%mem' -p "$pid";
  done
  kill "$pid"
)

topp sudo ./encrypted_covert_channel --client $cct --is_encrypted $cipher_type &
#sudo ./encrypted_covert_channel --client $cct --is_encrypted $cipher_type &
#echo $!
#if ps -p $! > /dev/null
#then
#   echo "$! is running"
#   ps -p $! -o %cpu
#   # Do something knowing the pid exists, i.e. the process with $PID is running
#fi


echo ""
echo "-------------------------------- Tests finished --------------------------------"
