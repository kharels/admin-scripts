#!/bin/bash
# 
# Author: Shashank Kharel
# Email: shashank.kharel@hms.com
# Date: 10/10/2017
# 
# This script configures and runs kdump for collection of core dump locally on /var/crash
# 
############################################################################################

RHEL_VERSION=`cat /etc/redhat-release | awk '{ print $7 }'| awk -F. '{ print $1 }'`
yum -y install kexec-tools

# Fix kdump.conf file
cp /etc/kdump.conf /etc/kdump.conf-bkup-`date +%m%d%y`
sed -i 's/^\([^#]\)/#\1/g' /etc/kdump.conf

cat << EOF >> /etc/kdump.conf

path /var/crash
core_collector makedumpfile -c
default reboot
EOF

# Fix kernel parameter in grub.conf

if [[ $RHEL_VERSION -eq 6 ]]; then
        sed 's/crashkernel=auto/crashkernel=128M/g' /boot/grub/grub.conf
	sed 's/crashkernel=[^ ]*[ ] *//' /boot/grub/grub.conf
	chkconfig kdump on 
	
elif [[ $RHEL_VERSION -eq 7 ]]; then
	sed 's/crashkernel=auto/crashkernel=128M/g' /boot/grub2/grub.cfg
	sed 's/crashkernel=[^ ]*[ ] *//' /boot/grub2/grub.cfg
        grub2-mkconfig -o /boot/grub2/grub.cfg
	systemctl enable kdump
	systemctl start kdump

else
	echo "Email shashank.kharel@hms.com to request script to be updated for `uname -r`"
fi

exit 0 
