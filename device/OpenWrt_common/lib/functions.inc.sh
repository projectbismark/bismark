#!/bin/ash
# Ausiliary functions library
#
# author: walter.dedonato@unina.it

# Generates integer random numbers
# $1 = min value
# $2 = max value
random ()
{
	diff=$(( $2 - $1 ))
	awk '{
		srand($1*100);
		print '$1' + int(rand()*'$diff');
	}' /proc/uptime
}

# Modifies configuration files option
# $1 = configuration file
# $2 = option
# $3 = value
mod_conf ()
{
	if [ "$3" ]; then
		# Modify value
		sed -i -e "/^$2=/ s/=.*/=\"$3\"/" $1
	else
		# Remove option
		sed -i -e "/^$2=/ d" $1
	fi
}

# Log output destination
# $1 = action
output ()
{
        if [ $REMOTE ]; then
                ( echo "$DEVICE_ID log $1 $(date +%s)" ; cat ) | nc -u $NC_OPTS $SERVER $PROBE_PORT
        else
                cat
        fi
}

# Rename dump files
rename_dump ()
{
	# Rename features dump files
	( cd /tmp/measure/
	  for file in $(find -name "*.dump"); do
		mv $file ${DEVICE_ID}_${file:2}
	  done
	)
}

# Get public IP
get_ip ()
{
	if [ -e /tmp/bismark/var/ip ] && [ $(grep -c '^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$' /tmp/bismark/var/ip) -ge 1 ]; then
		src=$(cat /tmp/bismark/var/ip)
	else
		src=$(ifconfig $WAN_IF | awk '/inet addr:/{ print substr($2,6) }')
	fi
}

# Download file from URL. If 404, then write empty file

dl_file ()
{
	curl -f --output $2 $1
	if [ $? -gt 0 ]; then
		echo -n "" > $2
	fi
}

# Atomically acquire the measurement lock.
# Arguments: process names to kill when expiring the lock.
# CAUTION: These process names should be unique to this active
# measurement, otherwise there will be collateral damage when
# the lock is expired and these processes are killed.
# Returns: 0 if locking was successful, nonzero if unsuccessful.
acquire_active_measurements_lock ()
{
	(set -o noclobber; busybox echo "$*" > $ACTIVE_MEASUREMENTS_LOCK_FILE)
}

# Atomically release the measurement lock.
# Returns: 0 if successful, nonzero if lock was already released.
release_active_measurments_lock ()
{
	busybox rm $ACTIVE_MEASUREMENTS_LOCK_FILE
}

# Print the timestamp when the mlock was last locked.
# Returns: 0 if lock exists and we could get its creation time; nonzero otherise
active_measurements_lock_creation_time ()
{
	if ! stat_result=$(busybox stat -t $ACTIVE_MEASUREMENTS_LOCK_FILE); then
		return $?
	fi
	echo $stat_result | busybox cut -d" " -f13
}

# Check if the active measurements lock has expired. If it has, expire the lock
# by killing its processes and releasing the lock.
# Returns: 0 if successful, nonzero on error.
expire_active_measurements_lock ()
{
	if ! processes_to_kill=$(busybox cat $ACTIVE_MEASUREMENTS_LOCK_FILE); then
		return $?
	fi
	if ! locktime=$(active_measurements_lock_creation_time); then
		return $?
	fi
	currtime=$(busybox date +%s)
	if [ $((currtime - locktime)) -lt $ACTIVE_MEASUREMENTS_MAX_DURATION_SECONDS ]; then
		return 0
	fi
	# There's a race condition here. Between getting the lock creation time
	# and releasing the lock, it's possible that the lock has been released
	# and subquently acquired by someone else, who shouldn't be expired or
	# released at this time. The chance of this happening is very low,
	# but you never know...
	if ! release_active_measurments_lock; then
		return 0
	fi
	for process in $processes_to_kill; do
		busybox killall $process
	done
}
