#!/bin/ksh

# Setting some variables

my_date_long=`date +%m%d%y-%H%M%S`
my_date_short=`date +%m%d%y-%H%M`
no_of_samples=5
time_int=1

# Collect Raw data
function collect_ent {
	cpu_ent_file=`lparstat $time_int $no_of_samples| awk '{ print $5 }'| tail -${no_of_samples} >/tmp/cpu_ent_monitor-${my_date_long}`
	get_sum_cpu=`cat /tmp/cpu_ent_monitor-${my_date_long}| paste -sd+ -| bc`
	res=$(echo "scale=4\n$get_sum_cpu / $no_of_samples" | bc)
	#echo $(( $get_sum_cpu / $no_of_samples )) 
	echo $res
}



# echo "No of physical CPU cores used at" $my_date_long - `collect_ent`

# Collect 12 samples
i=1
while (( i <= 48 ))
do
	new_date=`date +%m%d%y-%H%M%S`
	echo "CPU cores used" - $new_date - `collect_ent`>> /var/log/physical_cpu_usage.log
#	echo "CPU cores used" - $new_date - `collect_ent`
	(( i += 1 ))
done
