#!/usr/bin/ksh
##########################
##
## This script is used to create a mksysb image of a server
##
##########################
TheHost=$1
echo "$TheHost"

###  Check that the client Server has been defined  #####
lsnim -l $TheHost > /dev/null 2>&1
rc=$?
if [[ $rc != 0 ]] ; then
  echo "You need to add $TheHost to NIM machines before running this script"
  exit
fi
echo here1

### Remove the mksysb resource if it exists #####
lsnim -l "$TheHost"_mksysb > /dev/null 2>&1
rc=$?
if [[ $rc = 0 ]] ; then
  echo "Removing old mksysb resource from NIM"
  nim -o remove "$TheHost"_mksysb
fi
echo here2

if [ ! -d /export/mksysbrepos2/$TheHost ];then
  mkdir /export/mksysbrepos2/$TheHost
fi
echo here3

###  Add the mksysb to the NIM resources  #####
nim -o define -t mksysb -F -a server=master \
-a location=/export/mksysbrepos2/"$TheHost"/"$TheHost"_mksysb  \
-a source="$TheHost" -a mk_image=yes -a mksysb_flags=p -a comments="Created on `date`" \
"$TheHost"_mksysb 
