#!/bin/bash

# init ssh port
if [ -z $1 ];
then
    SSH_PORT=10021
else
    SSH_PORT=$1
fi

DIR=$(dirname $(realpath -s $0))
list=($DIR/*.id_rsa)
KEY=${list[0]}

ssh -i $KEY -p $SSH_PORT -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" root@localhost