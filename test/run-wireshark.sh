#!/bin/bash

. ./common.sh
aptInstall "wireshark"

echob "Starting Wireshark with support for SUPERMAN..."
wireshark -X lua_script:superman.lua
