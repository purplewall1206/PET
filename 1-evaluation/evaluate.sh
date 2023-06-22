#!/bin/bash

# create image
# ./create-image.sh


gnome-terminal --title="terminal1: RUN VM & POC here"  -- ./run-native.sh 
sleep 5

./copy2vm.sh ./linux-5.15-vulns/samples/bpf/
./copy2vm.sh ../2-source-code/POCs/
./copy2vm.sh scripts/

gnome-terminal --title="terminal2: RUN BPF & MONITOR OUTPUT here" -- ./connect2vm.sh

