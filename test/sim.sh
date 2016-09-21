#!/bin/bash

. ./common.sh

aptInstall "qemu uml-utilities bridge-utils gnome-terminal"

echob Starting simulation...
sudo sleep 0.1

./run.sh 2 &
sleep 5
./run.sh 3 &
#sleep 5
#./run.sh 4 &
wait
