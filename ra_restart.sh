#!/bin/bash
# 
# Author: Shashank Kharel
# Email: shashank.kharel@hms.com
# Version: 0
# Relase: 0.1
# 
# This script will allow to restart RA agents on the remote server.
# This can be done in two ways:
#   - Restart all agents
#   - Restart agent on particular host
#
# CHANGE LOG
# - added logic to account to servers that run the agent as cascm user
#
# HOW TO
# To setup SSH keys in order to restart the agents 
# Public key (/home/cascm/id_rsa.pub) has to be copied to home directory of svccascm user in the server 
# where agent is installed (~svccascm/.ssh/)
#
# Example: ssh-copy-id -i ~cascm/.ssh/id_rsa.pub svccascm@<SERVER_NAME>
# - to execute the above command sucessfully you will need to have password to svccascm service account
#
########################################################################################################
# set -x
#
# Add check for $1 and $2
case $1 in
	-h)
		ssh -q -t $2 "/opt/CA/ReleaseAutomationAgent/nolio_agent.sh restart"
			server=$2
		        if [ \( "$server" == "lpappctrl001" \) -o \( "$server" == "lpapphar160" \) ]; then
                                ssh -q -t cascm@$server "/opt/CA/ReleaseAutomationAgent/nolio_agent.sh restart"
                        else
                                ssh -q -t svccascm@$server "/opt/CA/ReleaseAutomationAgent/nolio_agent.sh restart"
                        fi

	;;

	-f)
		for server in `cat $2`; do 
			echo $server
			ssh -q -t $server "/opt/CA/ReleaseAutomationAgent/nolio_agent.sh restart"
		done
	;;

	*)
		echo ""
		echo "Select -h for particular host and -f for input file that constains hostlist."
		echo "You could also restart all agents, would you like to continue?(Y/N)"
		read RESPONSE
		if [ "$RESPONSE" == "Y" ]; then
	                for server in `cat $2`; do
      		                 echo $server
                        ssh -q -t $server "/opt/CA/ReleaseAutomationAgent/nolio_agent.sh restart"
                done

		else
			echo "No action taken"
			exit 0
		fi
		echo ""
	;;
esac
