#!/bin/bash
# RUN FROM SERVER LOCATION

echo "-------------------------------- Performing cryptography tests --------------------------------"

# Variables
project_path_client="/home/pi/encrypted_covert_channel/build"
result_path="/home/pi/results"
repeat_number=20
cd $project_path_client

for cipher_type in clefia aes des present rsa grain
do
  echo "Testing covert channel type : cipher: $cipher_type"

  output_path="${result_path}/cpu_output_${cipher_type}.csv"
  logs_path="${result_path}/cpu_logs_${cipher_type}.csv"
  echo "$output_path"
  for i in $(seq 1 1 $repeat_number)
  do
    /usr/bin/time -f "%P; %M"  -o o.txt sudo ./encrypted_covert_channel --crypto_test  $cipher_type 1000
    cat o.txt >> $output_path
    sleep 3
  done
  sleep 5
done

echo ""
echo "-------------------------------- Tests finished --------------------------------"
