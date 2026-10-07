# Shell functions that are common between Linux versions.
buddyinfo()
{
	$ATLAS_MEASUREMENT/buddyinfo "$@"
	set $(free | grep 'Mem:')
	[ $(expr $3 + $5) -gt 2048 ]
}
epoch()
{
	date '+%s'
}
rchoose()
{
	$ATLAS_MEASUREMENT/rchoose "$@"
}
check_pid()
{
	[ -d "/proc/$@" ]
}
condmv()
{
	$ATLAS_MEASUREMENT/condmv "$@"
}
dfrm()
{
	$ATLAS_MEASUREMENT/dfrm "$@"
}
evping()
{
	$ATLAS_MEASUREMENT/evping "$@"
}
evping_no_check()
{
	ATLAS_DISABLE_CHECK_ADDR=yes $ATLAS_MEASUREMENT/evping "$@"
}
httppost()
{
	$ATLAS_MEASUREMENT/httppost "$@"
}
ping()
{
	$ATLAS_LIBEXECDIR/ping "$@"
}
rxtxrpt()
{
	$ATLAS_MEASUREMENT/rxtxrpt "$@"
}
rptaddrs()
{
	$ATLAS_MEASUREMENT/rptaddrs "$@"
}
rptuptime()
{
	$ATLAS_MEASUREMENT/rptuptime "$@"
}
onlyuptime()
{
	$ATLAS_MEASUREMENT/onlyuptime "$@"
}
#telnetd()
#{
#	$SU_CMD $ATLAS_MEASUREMENT/telnetd "$@"
#}
perd()
{
	$SU_CMD $ATLAS_MEASUREMENT/perd "$@"
}
root_perd()
{
	$ATLAS_MEASUREMENT/perd "$@"
}
ooqd()
{
	$SU_CMD $ATLAS_LIBEXECDIR/ooqd "$@"
}
eperd()
{
	$SU_CMD $ATLAS_MEASUREMENT/eperd "$@"
}
eooqd()
{
	$SU_CMD $ATLAS_MEASUREMENT/eooqd "$@"
}
sleepkick()
{
	sleep "$1"
}
kill_ssh()
{
	if [ -f $STATUS_DIR/con_keep_pid.vol ]
	then
		kill -9 `cat $STATUS_DIR/con_keep_pid.vol` 2>/dev/null
	rm -f $STATUS_DIR/con_keep_pid.vol
	fi
}
findpid_ssh()
{
	[ -f $STATUS_DIR/con_keep_pid.vol ] &&
		kill -0 `cat $STATUS_DIR/con_keep_pid.vol` 2>/dev/null
}
kill_perds()
{
	PERD_PIDS=`pidof perd`
	for s in $PERD_PIDS
	do
		kill -9 $s 2>/dev/null
	done

	EPERD_PIDS=`pidof eperd`
	for s in $EPERD_PIDS
	do
		kill -9 $s 2>/dev/null
	done

	EOOQD_PIDS=`pidof eooqd`
	for s in $EOOQD_PIDS
	do
		kill -9 $s 2>/dev/null
	done
}
kill_telnetd()
{
	if [ -f $STATUS_DIR/telnetd-port$TELNETD_PORT-pid.vol ] ; then
		kill -9 `tail -1 $STATUS_DIR/telnetd-port$TELNETD_PORT-pid.vol` 2>/dev/null
	fi
}
get_sos_server()
{
	sos_env=$(cat "$MODE_FILE" 2>/dev/null)
	case X$sos_env in
	Xdev|Xtest|Xprod)
	;;
	*)
		# Failover
		sos_env=prod
	;;
	esac
	echo "sos.$sos_env.atlas.ripe.net"
}
sos()
{
	## sos
	UPTIME=`sed 's/\..*//' < /proc/uptime`
	INFO="$1"
	CLOCK="$(date '+%s')"
	if [ -n "$INFO" ]; then INFO="$INFO".; fi
	evping -e -c 2 "${INFO}C${CLOCK}.U$UPTIME.M$ETHER_SCANNED.$(get_sos_server)"
}
ssh()
{
	/usr/bin/ssh -i "$SSH_PVT_KEY" -o "ServerAliveInterval 60" \
		-o "StrictHostKeyChecking yes" \
		-o "UserKnownHostsFile $ATLAS_STATUS/known_hosts" "$@"
}
ssh_exec()
{
	exec /usr/bin/ssh -i "$SSH_PVT_KEY" -o "ServerAliveInterval 60"\
		-o "StrictHostKeyChecking yes" \
		-o "UserKnownHostsFile $ATLAS_STATUS/known_hosts" "$@"
}
get_ether_addr()
{
	# We get the MAC address of the probe's interface, in a way that's not
	# dependent on net-tools or iproute2, but it is Linux-specific!

	# Get default-route iface, not merely the first one
	dev=
	# v4-only
	while read -r iface dest gw flags refcnt use metric mask rest ; do
		if [ "$dest" = "00000000" ] && [ "$mask" = "00000000" ] ; then
			dev=$iface ; break
		fi
	done < /proc/net/route
	# if v4 failed, v6-only
	if [ -z "$dev" ] && [ -r /proc/net/ipv6_route ] ; then
		while read -r dest plen snet splen nhop metric refcnt use flags iface ; do
			if [ "$dest" = "00000000000000000000000000000000" ] && [ "$plen" = "00" ] && [ "$iface" != "lo" ] ; then
				dev=$iface ; break
			fi
		done < /proc/net/ipv6_route
	fi
	ETHER_ADDR=`cat "/sys/class/net/$dev/address" 2>/dev/null`
	export ETHER_ADDR
	ETHER_SCANNED=`echo $ETHER_ADDR | sed -e s/\://g`; export ETHER_SCANNED
}
dump_interfaces()
{
	# 1. `ip -s a` is the best replacement to `ifconfig`
	if ip -s a > /dev/null 2>&1 ; then
		ip -s a
	# 2. Busybox doesn't support `-s`, so we drop it for `ip a`
	elif ip a > /dev/null 2>&1 ; then
		ip a
		cat /proc/net/dev
	# 3. deprecated `ifconfig` still works
	elif command -v ifconfig > /dev/null 2>&1 ; then
		ifconfig
	# 4. Otherwise things are genuinely broken
	else
		echo "dump_interfaces: missing 'ip' or 'ifconfig'; install iproute2 (or deprecated net-tools)" 1>&2
		cat /proc/net/dev
	fi
}
set_date_from_currenttime_txt()
{
	if [ -f $STATUS_DIR/currenttime.txt ]
	then
		t=`cat $STATUS_DIR/currenttime.txt`
		echo Setting time to $t
		date -S -s "$t"
		D=`epoch`
		echo "RESULT 9004 done $D after setting time from currenttime.txt to $t" >> $DATA_NEW_DIR/simpleping
	else
		echo no file $STATUS_DIR/currenttime.txt
	fi
}
do_buddyinfo()
{
	lowmem="$1"
	logfile="$2"

	if [ -n "$logfile" ]
	then
		buddyinfo "$lowmem" >> "$logfile"
	fi
	buddyinfo "$lowmem"
}
hash_ssh_pubkey()
{
	hash=$(sed < "$1" 's/^[^ ]* *\([^ ]*\).*/\1/' |
		tr -d '\n' | sha256sum)
	expr "$hash" : "\(.\{16\}\)"
}
config_lookup()
{
	key="$1"
	default_value="$2"

	# Look for options in config.txt
	if [ ! -f "$CONFIG_TXT" ]
	then
		echo "$default_value"
		return
	fi
	value=$(sed < "$CONFIG_TXT" -n "s/^[ 	]*$key=\(.*\)/\1/p" |
		head -1 | sed 's/[ 	]*$//')
	if [ -n "$value" ]
	then
		echo "$value"
	else
		echo "$default_value"
	fi
}
