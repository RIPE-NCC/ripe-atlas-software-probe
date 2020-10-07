# Shell functions that are common between Linux versions.
buddyinfo()
{
	$BB_BIN_DIR/buddyinfo "$@"
	set $(free | grep 'Mem:')
	[ $(expr $3 + $5) -gt 2048 ]
}
epoch()
{
	date '+%s'
}
rchoose()
{
	$BB_BIN_DIR/rchoose "$@"
}
condmv()
{
	$BB_BIN_DIR/condmv "$@"
}
dfrm()
{
	$BB_BIN_DIR/dfrm "$@"
}
evping()
{
	$BB_BIN_DIR/evping "$@"
}
evping_no_check()
{
	ATLAS_DISABLE_CHECK_ADDR=yes $BB_BIN_DIR/evping "$@"
}
httppost()
{
	$BB_BIN_DIR/httppost "$@"
}
ping()
{
	$BB_BIN_DIR/ping "$@"
}
rxtxrpt()
{
	$BB_BIN_DIR/rxtxrpt "$@"
}
rptaddrs()
{
	$BB_BIN_DIR/rptaddrs "$@"
}
rptuptime()
{
	$BB_BIN_DIR/rptuptime "$@"
}
onlyuptime()
{
	$BB_BIN_DIR/onlyuptime "$@"
}
#telnetd()
#{
#	$SU_CMD $BB_BASE_DIR/usr/sbin/telnetd "$@"
#}
perd()
{
	$SU_CMD $BB_BASE_DIR/bin/perd "$@"
}
root_perd()
{
	$BB_BASE_DIR/bin/perd "$@"
}
ooqd()
{
	$SU_CMD $BB_BASE_DIR/bin/ooqd "$@"
}
eperd()
{
	$SU_CMD $BB_BASE_DIR/bin/eperd "$@"
}
eooqd()
{
	$SU_CMD $BB_BASE_DIR/bin/eooqd "$@"
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
		-o "UserKnownHostsFile $SSH_DIR/known_hosts" "$@"
}
ssh_exec()
{
	exec /usr/bin/ssh -i "$SSH_PVT_KEY" -o "ServerAliveInterval 60"\
		-o "StrictHostKeyChecking yes" \
		-o "UserKnownHostsFile $SSH_DIR/known_hosts" "$@"
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
