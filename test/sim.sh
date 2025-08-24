#!/bin/bash

. ./common.sh

aptInstall "qemu-system uml-utilities bridge-utils dbus-x11 gnome-terminal"

echob Starting simulation...
sudo sleep 0.1

./run.sh 2 &
sleep 5
./run.sh 3 &
#sleep 5
#./run.sh 4 &
wait
