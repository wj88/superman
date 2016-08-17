#!/bin/bash

. ./common.sh

echob Starting simulation...
echo "	Requesting sudo permission..."
sudo echo "	... sudo permission granted."

./run.sh 2 &
sleep 5
./run.sh 3 &
#sleep 5
#./run.sh 4 &
wait
