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
		print '$2' + int(rand()*'$diff');
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
	if [ -e /tmp/ip ] && [ $(grep -c '^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$' /tmp/ip) -ge 1 ]; then
		src=$(cat /tmp/ip)
	else
		src=$(ifconfig $WAN_IF | awk '/inet addr:/{ print substr($2,6) }')
	fi
}

# Wifi output filter
wifi_filter ()
{
        ( cd /tmp/measure/
	  [ $PRIVACY_MODE ] && OPT="-v priv=on"
          for file in $(find -name "*.csv" -a ! -name "*.filt.*"); do
                awk $OPT -F", |," -f /dev/stdin $file > ${file%.*}.filt.csv <<-end
			function tstamp(d,ts){
				cmd = "date -d \"" d "\" +%s"
				cmd | getline ts
				close(cmd)
				return ts
			}
			function hash(n,h){
				cmd = "echo " n " | md5sum"
				cmd | getline h
				close(cmd)
				return substr(h,1,10)
			}
			/^BSSID/{ 
				sec = 1
				printf "%-18s %-11s %-11s %-2s %-5s %-8s %-10s %-4s %-5s %-7s %-7s %-5s %s\n",\
				"BSSID", "First", "Last", "Ch", "Speed", "Privacy", "Cipher", "Auth", "Power", "Beacons", "IVs", "IDlen", "ESSID" 
			}
			/^Station/{ 
				sec = 2
				printf "%-18s %-11s %-11s %-5s %-7s %-18s %s\n",\
				"Station MAC", "First", "Last", "Power", "Pkts", "BSSID", "ESSID" 
			}
			{ 
				if (\$1 ~ /^..:/) {
					# First MAC
					if (priv == "on") \$1 = substr(\$1,1,8) ":00:00:00"
					\$2 = tstamp(\$2)
					\$3 = tstamp(\$3)
					if (sec == 1) {
						if (\$6 ~ /[A-Za-z0-9]+/) { gsub(/ /,"+",\$6); sub(/+$/,"",\$6) } else { \$6 = "-" }
						if (\$7 ~ /[A-Za-z0-9]+/) { gsub(/ /,"+",\$7) } else { \$7 = "-" }
						if (\$8 ~ /[A-Za-z0-9]+/) { gsub(/ /,"+",\$8) } else { \$8 = "-" }
						if (\$14 ~ /[A-Za-z0-9]+/) { if (priv == "on") \$14 = hash(\$14) } else { \$14 = "-" }
						printf "%-18s %-11u %-11u %-2u %-5d %-8s %-10s %-4s %-5d %-7u %-7u %-5u %s\n",\
							\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$13, \$14 
					} else  if ( sec == 2 ) { 
						if (\$6 ~ /^..:/) { if (priv == "on") \$6 = substr(\$6,1,8) ":00:00:00" } else { \$6 = "-" }
						if (\$7 ~ /[a-zA-Z0-9]+/) { if (priv == "on") \$7 = hash(\$7) } else { \$7 = "-"}
						printf "%-18s %-11u %-11u %-5d %-7d %-18s %s\n",\
							\$1, \$2, \$3, \$4, \$5, \$6, \$7 
					}
				} 
			}
		end
		rm $file
          done
        )
}

# T2 privacy filter
t2_filter ()
{
        ( cd /tmp/measure/
          for file in $(find -name "*.t2" -a ! -name "*.filt.*"); do
                awk -f /dev/stdin $file > ${file%.*}.filt.t2 <<-end
			function anon(ip,d){
				split(ip,d,".")
				return d[1]"."d[2]"."d[3]".0" 
			}
			{ 
				if (\$1 ~ /^[0-9]/) {
					\$2 = anon(\$2)
					\$3 = anon(\$3)
					printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",\
						\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12, \$13, \$14, \$15
				} else {
					print
				}
			}
		end
		rm $file
          done
        )
	
}

