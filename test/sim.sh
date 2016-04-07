#!/bin/bash

./run.sh 2 &
sleep 5
./run.sh 3 &
wait
