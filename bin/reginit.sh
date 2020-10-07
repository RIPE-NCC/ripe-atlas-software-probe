#!/bin/sh
#
# Handel registering with ATLAS regservers
# 2010 Oct Antony Antony

#exec >/tmp/reginit.out 2>/tmp/reginit.err
#set -x

STATE_FILE=$1

. $ATLAS_STATIC/bin/arch/$DEVICE_NAME/$DEVICE_NAME-reginit.sh

. $BIN_DIR/common.sh

## Probe

# Common
[ -z "$SSH_PVT_KEY" ] && SSH_PVT_KEY=$BASE_DIR/etc/probe_key
# Set REG_SERVERS if it isn't set already
[ -z "$REG_SERVERS" ] && REG_SERVERS=$BIN_DIR/reg_servers.sh
CON_INIT_CONF=./con_init_conf.txt
CON_INIT_REPLY=con_init_reply.txt
CON_KEEP_CONF=./con_keep_conf.txt
CON_KEEP_REPLY=con_keep_reply.vol
RESOLV_CONF_VOL=resolv.conf.vol
SSH_OUT=ssh_out.txt
LOW_MEM_T=512
export TZ=UTC

if [ -f $STATE_FILE ] ; then
	echo "there is a state file $STATE_FILE. another copy running".
	exit 0
else
	echo "ATLAS registration starting"
	touch  $STATE_FILE
fi

## Connect to reg server
cd $STATUS_DIR

. $REG_SERVERS

need_rereg=1
R=NEW

if [ -f $FORCE_REG ] ; then
	# Ignore the reason.
	rm -f $CON_INIT_CONF
	rm -f $CON_KEEP_CONF
	R=FORCE_REG
	need_rereg=1
	echo "REASON_FOR_REGISTRATION $R FORCED"
elif [ ! -f $CON_INIT_CONF ] ; then
	R="NEW"
	need_rereg=1
	echo "REASON_FOR_REGISTRATION $R NO previous state files"
else
	unset CONTROLLER_1_HOST
	unset CONTROLLER_1_PORT
	unset REREG_TIMER
	while read line
	do
		if [ -z "$line" ]
		then
			echo >&2 "Shell returned empty line in CON_INIT_CONF (1)"
			break
		fi
		set -- $line
                kw="$1"
                value="$2"
		case "$kw" in
		CONTROLLER_1_HOST) CONTROLLER_1_HOST="$value" ;;
		CONTROLLER_1_PORT) CONTROLLER_1_PORT="$value" ;;
		FIRMWARE_KERNEL_VERSION) FIRMWARE_KERNEL_VERSION="$value" ;;
		FIRMWARE_KERNEL_CS_ALG) FIRMWARE_KERNEL_CS_ALG="$value" ;;
		FIRMWARE_KERNEL_CS_COMP) FIRMWARE_KERNEL_CS_COMP="$value" ;;
		FIRMWARE_KERNEL_CS_UNCOMP) FIRMWARE_KERNEL_CS_UNCOMP="$value" ;;
		FIRMWARE_KERNEL) FIRMWARE_KERNEL="$value" ;;
		FIRMWARE_APPS_VERSION) FIRMWARE_APPS_VERSION="$value" ;;
		FIRMWARE_APPS_CS_ALG) FIRMWARE_APPS_CS_ALG="$value" ;;
		FIRMWARE_APPS_CS_COMP) FIRMWARE_APPS_CS_COMP="$value" ;;
		FIRMWARE_APPS_CS_UNCOMP) FIRMWARE_APPS_CS_UNCOMP="$value" ;;
		FIRMWARE_APPS) FIRMWARE_APPS="$value" ;;
		REREG_TIMER) REREG_TIMER="$value" ;;
		REG_WAIT_UNTIL) REG_WAIT_UNTIL="$value" ;;
		*)
			echo >&2 "unknown keyword '$kw' in CON_INIT_CONF (1)"
		;;
		esac
	done < $CON_INIT_CONF
	NOW=`epoch`
	# the wait one came from previous reg attemp reply was wait.
	if [ -n "$REG_WAIT_UNTIL" ] ; then
		echo "there is WAIT, REG_WAIT_UNTIL  $REG_WAIT_UNTI, now is $NOW"
		if [ $REG_WAIT_UNTIL -le $NOW ] ; then
			echo " REG_WAIT_UNTIL expired go re-reg $REG_WAIT_UNTIL now $NOW"
			need_rereg=1
			R=WAIT_OVER
			REG_WAIT_UNTIL=1
		else
			need_rereg=0
			echo "wait to re-register is not over, REG_WAIT_UNTIL $REG_WAIT_UNTIL , now is $NOW "
       			exit
		fi
	elif [ -n "$REREG_TIMER" ] ; then
		if [ $REREG_TIMER -le $NOW ] ; then
	      		echo "REREG_TIMER $REREG_TIMER expired now is $NOW"
              		R=REREG_TIMER_EXPIRED
              		need_rereg=1
	      		REREG_TIMER=1
  	      		echo "REREG_TIMER_EXPIRED  go re register REREG_TIMER $REREG_TIMER  , now is $NOW  "
		else
			echo "registration info is still valid till $REREG_TIMER, now $NOW"
			need_rereg=0
		fi
	fi
fi

if [ "$need_rereg" = 1 ]; then
	rm -f $CON_KEEP_CONF
	R_HOST=`rchoose $REG_1_HOST $REG_2_HOST $REG_3_HOST $REG_4_HOST $REG_5_HOST $REG_6_HOST`
	echo "REGHOSTS $REG_1_HOST $REG_2_HOST $REG_3_HOST $REG_4_HOST $REG_5_HOST $REG_6_HOST"
	$BUDDYINFO $LOW_MEM_T $DATA_NEW_DIR/simpleping
	if [ $? -eq 1 ] ; then
                D=`epoch`
                echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks "
                echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks " >> $DATA_NEW_DIR/simpleping
                reboot_probe
		exit
        fi
	D=`epoch`
	echo "RESULT 9011 done $D $ETHER_SCANNED Starting $SSH_CMD -p 443 atlas@$R_HOST INIT"  >> $DATA_NEW_DIR/simpleping
	echo "$SSH_CMD -p 443 atlas@$R_HOST INIT"
	$SET_LEDS_CMD reg-init
	$P_TO_R_INIT_CMD $R | $SSH_CMD $SSH_OPT -p 443 atlas@$R_HOST INIT > $REG_INIT_REPLY 2>$SSH_ERR
	ERR=$?
	if [ $ERR != "0" ] ; then
		D=`epoch`
		echo "RESULT 9011 done $D $ETHER_SCANNED ERR $ERR stdout" `cat $REG_INIT_REPLY`  >> $DATA_NEW_DIR/simpleping
		echo "RESULT 9011 done $D $ETHER_SCANNED stderr" `cat $SSH_ERR`  >> $DATA_NEW_DIR/simpleping
		echo "$ERR  REGINIT exit with error"
		$SET_LEDS_CMD reginit-fail
		rm  -f $STATE_FILE
		exit
	fi

	if [ -f $FORCE_REG ] ; then
		rm $FORCE_REG
	fi
	$ATLASINIT -r $ATLASINIT_DEVICE_OPT $REG_INIT_REPLY > $CON_INIT_CONF
	unset CONTROLLER_1_HOST
	unset CONTROLLER_1_PORT
	unset REREG_TIMER
	while read line
	do
		if [ -z "$line" ]
		then
			echo >&2 "Shell returned empty line in CON_INIT_CONF (2)"
			break
		fi
		set -- $line
		kw="$1"
		value="$2"
		case "$kw" in
		CONTROLLER_1_HOST) CONTROLLER_1_HOST="$value" ;;
		CONTROLLER_1_PORT) CONTROLLER_1_PORT="$value" ;;
		FIRMWARE_KERNEL_VERSION) FIRMWARE_KERNEL_VERSION="$value" ;;
		FIRMWARE_KERNEL_CS_ALG) FIRMWARE_KERNEL_CS_ALG="$value" ;;
		FIRMWARE_KERNEL_CS_COMP) FIRMWARE_KERNEL_CS_COMP="$value" ;;
		FIRMWARE_KERNEL_CS_UNCOMP) FIRMWARE_KERNEL_CS_UNCOMP="$value" ;;
		FIRMWARE_KERNEL) FIRMWARE_KERNEL="$value" ;;
		FIRMWARE_APPS_VERSION) FIRMWARE_APPS_VERSION="$value" ;;
		FIRMWARE_APPS_CS_ALG) FIRMWARE_APPS_CS_ALG="$value" ;;
		FIRMWARE_APPS_CS_COMP) FIRMWARE_APPS_CS_COMP="$value" ;;
		FIRMWARE_APPS_CS_UNCOMP) FIRMWARE_APPS_CS_UNCOMP="$value" ;;
		FIRMWARE_APPS) FIRMWARE_APPS="$value" ;;
		REREG_TIMER) REREG_TIMER="$value" ;;
		REG_WAIT_UNTIL) REG_WAIT_UNTIL="$value" ;;
		*)
			echo >&2 "unknown keyword '$kw' in CON_INIT_CONF (2)"
		;;
		esac
	done < $CON_INIT_CONF
	if [ -n "$REG_WAIT_UNTIL" ] ; then

		if [ $REG_WAIT_UNTIL -ge 2 ] ; then
			echo "reg server asked us to wait or there was an error. REG_WAIT_UNTIL $REG_WAIT_UNTIL"
			rm  -f $STATE_FILE
 			exit
		fi
	fi
	if [ -z "$CONTROLLER_1_HOST" ]; then
		echo "reg server didn't give a controller"
		rm -f "$STATE_FILE"
		exit
	fi
	echo "Got good controller info"
	cp $KNOWN_HOSTS_REG $SSH_DIR/known_hosts
	cat known_hosts_controllers >> $SSH_DIR/known_hosts
	NEED_REBOOT=0
	if [ -f $RESOLV_CONF_VOL ] ; then
		# If we have a default IPv6 interface then add that to
		# any link local addresses.
		if [ -n "$IPV6_INF" ]
		then
			# Only check for fe80. The prefix is in theory a
			# /10 but in practice a /64
			sed <$RESOLV_CONF_VOL >$RESOLV_CONF_VOL.tmp \
			"s/nameserver [fF][eE]80:[a-fA-F0-9:]*/&%$IPV6_INF/"
			mv $RESOLV_CONF_VOL.tmp $RESOLV_CONF_VOL

		fi

		if cmp $RESOLV_CONF_VOL $RESOLV_CONF_STATIC
		then
			:
		else
			NEED_REBOOT=1
		fi
		cp $RESOLV_CONF_VOL $RESOLV_CONF_STATIC
	else
		if [ -f $RESOLV_CONF_STATIC ]
		then
			echo "Delete the static DNS configuration and reboot"
			NEED_REBOOT=1
			rm -f $RESOLV_CONF_STATIC
		fi
	fi
	if [ -f $NETCONFIG_V4_VOL ] ; then
                MD5FULL=`md5sum $NETCONFIG_V4_VOL`
		set $MD5FULL
                MD5NEW=$1

		if [ -f $NETCONFIG_V4_DEST ] ; then
               		MD5FULL=`md5sum $NETCONFIG_V4_DEST`
			set $MD5FULL
                	MD5OLD=$1
		else
			MD5OLD=0
		fi

		if [ $MD5NEW !=  $MD5OLD ] ; then
			echo "RECEIVED NEW NETWORK CONFIGURATION COPY IT and REBOOT"
			rm -f $CON_INIT_CONF
        		rm -f $CON_KEEP_CONF
			cp $NETCONFIG_V4_VOL $NETCONFIG_V4_DEST
			$STATIC_V4_CMD $REG_INIT_REPLY
			NEED_REBOOT=1
		fi
	else
		if [ -f $NETCONFIG_V4_DEST ] ; then
			echo "Delete the static configuration and reboot"
			rm -f $NETCONFIG_V4_DEST
			$STATIC_V4_CMD $REG_INIT_REPLY
			NEED_REBOOT=1
		fi
	fi
	if [ -f $NETCONFIG_V6_VOL ] ; then
                MD5FULL=`md5sum $NETCONFIG_V6_VOL`
		set $MD5FULL
                MD5NEW=$1

		if [ -f $NETCONFIG_V6_DEST ] ; then
               		MD5FULL=`md5sum $NETCONFIG_V6_DEST`
			set $MD5FULL
                	MD5OLD=$1
		else
			MD5OLD=0
		fi

		if [ $MD5NEW !=  $MD5OLD ] ; then
			echo "RECEIVED NEW V6 NETWORK CONFIGURATION COPY IT and REBOOT"
			rm -f $CON_INIT_CONF
        		rm -f $CON_KEEP_CONF
			cp $NETCONFIG_V6_VOL $NETCONFIG_V6_DEST
			$STATIC_V6_CMD $REG_INIT_REPLY
			NEED_REBOOT=1
		fi
	else
		if [ -f $NETCONFIG_V6_DEST ] ; then
			echo "Delete the static configuration and reboot"
			rm -f $NETCONFIG_V6_DEST
			$STATIC_V6_CMD $REG_INIT_REPLY
			NEED_REBOOT=1
		fi
	fi
	if [ $NEED_REBOOT = 1 ]
	then
		reboot_probe
		exit
	fi
fi

$CHECK_FOR_NEW_KERNEL_CMD

## download image
if [ -f $STATUS_DIR/upgrade_firmware ]
then
	echo Moving failed log
	mv $STATUS_DIR/upgrade_firmware $DATA_NEW_DIR/upgrade_firmware
	condmv $DATA_NEW_DIR/upgrade_firmware $DATA_OUT_DIR/upgrade_firmware
elif [ -n "$FIRMWARE_APPS" ] ; then
	FIRMWARE_APPS_VERSION_MY=`cat $STATE_DIR/FIRMWARE_APPS_VERSION`
	if [ $FIRMWARE_APPS_VERSION -gt  $FIRMWARE_APPS_VERSION_MY ] ; then
		echo "there is a newer FIRMWARE_APPS_VERSION  $FIRMWARE_APPS_VERSION, current one is $FIRMWARE_APPS_VERSION_MY"
		echo "fetching it from -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST FIRMWARE_APPS $FIRMWARE_APPS"

		D=`epoch`
		echo "RESULT 9013 done $D $ETHER_SCANNED newer firmware $FIRMWARE_APPS_VERSION, currently running $FIRMWARE_APPS_VERSION_MY"  >> $DATA_NEW_DIR/simpleping

		# Make space
		rm -f $DATA_DIR/*
		rm -f $DATA_NEW_DIR/*
		rm -f $DATA_OUT_DIR/*
		rm -f *.bz2

		# Kill cronjobs
		rm $BASE_DIR/crons/*/*
		for i in $BASE_DIR/crons/*
		do
			echo root > $i/cron.update
		done

		# Remove any old firmware downloads left behind.  next line  could be removed.
		rm -f $FIRMWARE_FETCH_DIR/app_* $FIRMWARE_TARGET_DIR/app_*
		$BUDDYINFO $LOW_MEM_T $DATA_NEW_DIR/simpleping
        	if [ $? -eq 1 ] ; then
                	D=`epoch`
                	echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks "
			echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks " >> $DATA_NEW_DIR/simpleping
                	reboot_probe
			exit
		fi
		D=`epoch`
		echo "RESULT 9011 done $D $ETHER_SCANNED Starting $SSH_CMD -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST FIRMWARE_APPS $FIRMWARE_APPS"  >> $DATA_NEW_DIR/simpleping
		$SSH_CMD $SSH_OPT -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST  "FIRMWARE_APPS $FIRMWARE_APPS" > $FIRMWARE_FETCH_DIR/$FIRMWARE_APPS 2>$SSH_ERR
		ERR=$?
	        if [ $ERR != "0" ] ; then
			D=`epoch`
			echo "RESULT 9011 done $D $ETHER_SCANNED ERR $ERR stderr" `cat $SSH_ERR`  >> $DATA_NEW_DIR/simpleping
		fi

		checksum_okay=false
		signature_okay=false

		echo "check md5 of $FIRMWARE_APPS"
		MD5FULL=`md5sum $FIRMWARE_FETCH_DIR/$FIRMWARE_APPS`
		set $MD5FULL
		MD5=$1

		if [ $MD5 =  $FIRMWARE_APPS_CS_COMP ] ; then
			# the checksums match schedule an upgrade
			echo "checksums match $MD5 $FIRMWARE_APPS_CS_COMP "
			checksum_okay=true
		else
			#AA if the checksum faile what next??
			echo "checksums failed. $FIRMWARE_APPS"
			echo "Ignore upgrade and proceed to Controller for INIT"
		fi

		if [ $checksum_okay = true ]
		then
			if $CHECK_SIG_CMD $FIRMWARE_FETCH_DIR/$FIRMWARE_APPS SIGNATURE_APPS
			then
				echo "Found good signature"
				signature_okay=true
			fi
		fi

		if [ $checksum_okay = true -a $signature_okay = true ]
		then
			cp $CON_INIT_CONF $STATUS_DIR/FIRMWARE_APPS
			mv $FIRMWARE_FETCH_DIR/$FIRMWARE_APPS  $FIRMWARE_TARGET_DIR
			if [ -n "$DESKTOP" ] ; then
				echo "ready to reboot, but no this is not a probe";
			else
				$INSTALL_FIRMWARE_CMD $FIRMWARE_TARGET_DIR/$FIRMWARE_APPS
				rm $STATE_FILE
				reboot_probe
				exit
			fi
		fi
	else
		echo "IGNORE Firmware upgrade mine ,$FIRMWARE_APPS_VERSION_MY,  is new or the same $FIRMWARE_APPS_VERSION"
	fi
fi

###### Controller INIT
echo "check cached controller info from previous registration"
if [ -f $CON_KEEP_CONF ] ; then
	unset REMOTE_PORT
	unset CON_WAIT_TIMER
	while read line
	do
		if [ -z "$line" ]
		then
			echo >&2 "Shell returned empty line in CON_KEEP_CONF (1)"
			break
		fi
		set -- $line
		kw="$1"
		value="$2"
		case "$kw" in
		REMOTE_PORT) REMOTE_PORT="$value" ;;
		CON_WAIT_TIMER) CON_WAIT_TIMER="$value" ;;
		*)
			echo >&2 "unknown keyword '$kw' in CON_KEEP_CONF (1)"
		;;
		esac
	done < $CON_KEEP_CONF
fi
con_reinit=1
NOW=`epoch`

if [ -n "$CON_WAIT_TIMER" ] ; then
	if [ $CON_WAIT_TIMER -le $NOW ] ; then
  		echo "CON_WAIT_TIMER  $CON_WAIT_TIMER, timer expired now $NOW"
		rm $CON_KEEP_CONF
  		con_reinit=1
		CON_WAIT_TIMER=1
	else
  		echo "WAIT CON_WAIT_TIMER  $CON_WAIT_TIMER, now $NOW"
		rm -f $STATE_FILE
		exit
	fi

elif [ -n  "$REMOTE_PORT" ] ; then
	if [ -n $CONTROLLER_1_HOST ] ; then
		con_reinit=0
		echo "Use cached controller info -R $REMOTE_PORT atlas@$CONTROLLER_1_HOST"
	fi
else
	echo "NO cached controller info. NO REMOTE port info"
	echo "Do a controller INIT"
	con_reinit=1
fi

if [ "$con_reinit" = "1" ] ; then
## Controller  INIT
	$BUDDYINFO $LOW_MEM_T $DATA_NEW_DIR/simpleping
	if [ $? -eq 1 ] ; then
		D=`epoch`
		echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks "
		echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks " >> $DATA_NEW_DIR/simpleping
		reboot_probe
		exit
	fi
	D=`epoch`
	echo "RESULT 9011 done $D $ETHER_SCANNED Starting $SSH_CMD -p $CONTROLLER_1_PORT -i $SSH_PVT_KEY atlas@$CONTROLLER_1_HOST INIT"  >> $DATA_NEW_DIR/simpleping
	echo "Controller init -p  $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST  INIT"
	$SET_LEDS_CMD ctrl-init
	$SSH_CMD $SSH_OPT -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST INIT > $CON_INIT_REPLY 2>$SSH_ERR
	ERR=$?
	if [ $ERR != "0" ] ; then
		D=`epoch`
		echo "RESULT 9011 done $D $ETHER_SCANNED ERR $ERR stdout" `cat $CON_INIT_REPLY`  >> $DATA_NEW_DIR/simpleping
		echo "RESULT 9011 done $D $ETHER_SCANNED stderr" `cat $SSH_ERR`  >> $DATA_NEW_DIR/simpleping
		echo "$ERR controller INIT exit with error"
		rm  -f $STATE_FILE
		exit
	fi
	$ATLASINIT -c $CON_INIT_REPLY > $CON_KEEP_CONF
	unset REMOTE_PORT
	unset CON_WAIT_TIMER
	while read line
	do
		if [ -z "$line" ]
		then
			echo >&2 "Shell returned empty line in CON_KEEP_CONF (2)"
			break
		fi
		set -- $line
		kw="$1"
		value="$2"
		case "$kw" in
		REMOTE_PORT) REMOTE_PORT="$value" ;;
		CON_WAIT_TIMER) CON_WAIT_TIMER="$value" ;;
		*)
			echo >&2 "unknown keyword '$kw' in CON_KEEP_CONF (2)"
		;;
		esac
	done < $CON_KEEP_CONF
	rm -f $STATUS_DIR/con_hello_sent.vol
fi

if [ -n "$CON_WAIT_TIMER" ] ; then
	if [ $CON_WAIT_TIMER -gt $NOW ] ; then
		echo "Controller INIT told us to wait or there was an error wait until $CON_WAIT_TIMER"
		rm -f  $STATE_FILE
		exit
	fi
fi

###### Controller  KEEP
$BUDDYINFO $LOW_MEM_T $DATA_NEW_DIR/simpleping
if [ $? -eq 1 ] ; then
	D=`epoch`
	echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks "
	echo "RESULT 9009 done $D $ETHER_SCANNED REBOOT low memeory. $LOW_MEM_T K blocks " >> $DATA_NEW_DIR/simpleping
	reboot_probe
	exit
fi
D=`epoch`
echo "RESULT 9011 done $D $ETHER_SCANNED Starting $SSH_CMD -R $REMOTE_PORT:127.0.0.1:$TELNETD_PORT -L 8080:127.0.0.1:8080 -i $SSH_PVT_KEY -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST KEEP"  >> $DATA_NEW_DIR/simpleping
echo "initiating  KEEP connection to -R $REMOTE_PORT -p  $CONTROLLER_1_PORT $CONTROLLER_1_HOST"
$SET_LEDS_CMD keep-start
$SSH_CMD_EXEC $SSH_OPT -R $REMOTE_PORT:127.0.0.1:$TELNETD_PORT -L 8080:127.0.0.1:8080 -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST KEEP > $CON_KEEP_REPLY 2>$SSH_ERR &
KEEP_PID=$!
echo $KEEP_PID > $CON_KEEP_PID

ERR=$?
if [ $ERR != "0" ] ; then
 echo "non zero exit $ERR from controller KEEP"
 rm  -f $STATE_FILE
 exit
fi
## END
