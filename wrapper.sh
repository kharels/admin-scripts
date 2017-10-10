#!/bin/bash
#set -x

# $1 - flat file with hostlist
# $2 - name of the script with absolute path

for server in `cat $1`;do
  echo "########""$server"
  ssh -q -o "PasswordAuthentication no" -o "StrictHostKeyChecking no" -o 'ConnectTimeout=5' $server 'bash -s' <$2
done
