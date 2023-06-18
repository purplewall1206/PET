#!/bin/bash

# create image
./create-image.sh


gnome-terminal -- ./run-native.sh 
sleep 5

./copy2vm.sh bpf/
./copy2vm.sh ../2-source-code/POCs/
./copy2vm.sh scirpts/

gnome-terminal -- ./connect2vm.sh

