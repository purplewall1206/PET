#!/bin/bash

# sanity check
if [ -z $1 ];
then
    echo "please specify the path to the file you want to copy"
    exit
fi

# init ssh port
if [ -z $2 ];
then
    SSH_PORT=10021
else
    SSH_PORT=$2
fi

DIR=$(dirname $(realpath -s $0))
FILE=$(realpath $1)
list=($DIR/*.id_rsa)
KEY=${list[0]}

# echo $DIR
cd $DIR
cd ..
scp -r -i $KEY -P $SSH_PORT -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" $FILE root@localhost:~