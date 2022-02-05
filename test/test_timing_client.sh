#!/bin/bash
# RUN FROM SERVER LOCATION

echo "-------------------------------- Performing tests --------------------------------"

# Variables
repeat_number=20



for i in $(seq 1 1 $repeat_number)
do
	echo "Repeat number $i"
	sudo ./encrypted_covert_channel --client timing
	sleep 5
	echo "--- Sending finished ---"

done

echo "-------------------------------- Tests finished --------------------------------"
