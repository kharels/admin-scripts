#!/bin/bash
#
# Author: Shashank Kharel
# Email: shashank.kharel@hms.com
# Version: 0
# Relase: 0.1
#
# This script will monitor RA agents on the remote server and restart if necessary.
#
########################################################################################################
# set -x 
# write script block function
# write log with rotate function

LOGFILE="/home/cascm/scripts/logs/ra_monitor.log"

sk_logrotate()
{
 MaxFileSize=10240
 LOGFILE="/home/cascm/scripts/logs/ra_monitor.log"
 LOGDIR="/home/cascm/scripts/logs/"
 file_size=`du -k $LOGFILE | tr -s '\t' ' ' | cut -d' ' -f1`
 if [ $file_size -gt $MaxFileSize ];then   
        timestamp=`date +%s`
	mv $LOGFILE $LOGFILE.$timestamp 
	touch $LOGFILE
 fi 
 find $LOGDIR -type f -name *.log -mtime +45 -exec rm -rf {} \;
}

sk_logrotate

echo "">>${LOGFILE}
echo "*****************************************************************" >>${LOGFILE}
echo "*---------------------`date +%H%M%S-%m%d%Y`-----------------------------">>${LOGFILE}
echo "*****************************************************************">>${LOGFILE}
echo "">>${LOGFILE}

exec > >(tee -a ${LOGFILE}) 2>&1

# Monitor

for SERVER in `cat /home/cascm/scripts/server_list`; do
	nc -z -v -w5 $SERVER 8282 2&>1
	if [ $? -eq 0 ]; then
		echo "Agent running on ${SERVER}"
	else
		host ${SERVER} >/dev/null
		if [ $? -eq 0 ]; then
			echo "Agent offline on ${SERVER}, starting it now"
			/home/cascm/scripts/ra_restart.sh -h ${SERVER}
			if [ $? -eq 0 ]; then
				echo ""
			else
				echo ""
			fi
		else 
			echo "${SERVER} not found in DNS"
		fi
		# call script block
	fi
done

mail -s "RA nightly monitor log" shashank.kharel@hms.com </home/cascm/scripts/logs/ra_monitor.log
