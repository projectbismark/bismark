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
