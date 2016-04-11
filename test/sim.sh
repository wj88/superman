#!/bin/bash

. ./common.sh

echob Starting simulation...
echo "	Sudo is required."
sudo echo "		Sudo rights gained."

./run.sh 2 &
sleep 5
./run.sh 3 &
#sleep 5
#./run.sh 4 &
wait
