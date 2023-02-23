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
		kill -9 `cat $STATUS_DIR/con_keep_pid.vol`
	rm -f $STATUS_DIR/con_keep_pid.vol
	fi
}
findpid_ssh()
{
	[ -f $STATUS_DIR/con_keep_pid.vol ] &&
		kill -0 `cat $STATUS_DIR/con_keep_pid.vol`
}
kill_perds()
{
	PERD_PIDS=`pidof perd`
	for s in $PERD_PIDS
	do
		kill -9 $s
	done

	EPERD_PIDS=`pidof eperd`
	for s in $EPERD_PIDS
	do
		kill -9 $s
	done

	EOOQD_PIDS=`pidof eooqd`
	for s in $EOOQD_PIDS
	do
		kill -9 $s
	done
}
kill_telnetd()
{
	if [ -f $STATUS_DIR/telnetd-port$TELNETD_PORT-pid.vol ] ; then
		kill -9 `tail -1 $STATUS_DIR/telnetd-port$TELNETD_PORT-pid.vol`
	fi
}
sos()
{
	## sos
	UPTIME=`sed 's/\..*//' < /proc/uptime`
	INFO="$1"
	if [ -n "$INFO" ]; then INFO="$INFO".; fi
	evping -e -c 2 "${INFO}U$UPTIME.M$ETHER_SCANNED.sos.atlas.ripe.net"
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
	set $(ip link | grep 'link\/ether' | head -1)
	ETHER_ADDR=$2; export ETHER_ADDR
	ETHER_SCANNED=`echo $ETHER_ADDR | sed -e s/\://g`; export ETHER_SCANNED
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
	hash=$(sed < "$1" 's/^ssh-rsa *\([^ ]*\).*/\1/' |
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
