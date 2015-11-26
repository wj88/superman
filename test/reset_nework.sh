#!/bin/sh

sudo ifdown eth0; sudo ifdown br0; sudo ifup eth0; sudo ifup br0

