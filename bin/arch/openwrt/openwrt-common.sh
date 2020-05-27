# openwrt-common.sh
#
# Common definitions and functions between all openwrt-based probes

# Directories
HOME=/root; export HOME			# Somewhow, HOME is not set correctly
SSH_DIR=$HOME/.ssh; export SSH_DIR
BB_BASE_DIR=$BASE_DIR/bb-13.3; export BB_BASE_DIR
BB_BIN_DIR=$BB_BASE_DIR/bin; export BB_BIN_DIR
BB_SBIN_DIR=$BB_BASE_DIR/sbin; export BB_SBIN_DIR
RUN_DIR=/tmp/atlas-run

# We need DATA_NEW_DIR in this script
DATA_DIR=$BASE_DIR/data
DATA_NEW_DIR=$DATA_DIR/new

# Commands
TRIGGER_MANUAL_UPGRADE_CMD=trigger_manual_upgrade
TRY_UPGRADE_CMD=:
FINDPID_SSH_CMD=findpid_ssh
KILL_PERDS_CMD=kill_perds
KILL_SSH_CMD=kill_ssh
KILL_TELNETD_CMD=kill_telnetd
KILL_DHCPC_CMD=kill_dhcpc
MOUNT_FS_CMD=:
SETUP_NETWORK_CMD=setup_network
NTPCLIENT_CMD=:
RESOLVCONF_CMD=/home/atlas/bin/resolvconf
SU_CMD="sudo -E -u atlas"
CHOWN_FOR_MSM=chown_for_msm
CHMOD_FOR_MSM=:
AFTER_PASSWDSET=after_passwdset
CHOWN_DATA_DIRS=chown_data_dirs
HANDLE_STORAGE_CURRENT_TIME=handle_storage_current_time
LOAD_STORAGE_CURRENT_TIME=load_storage_current_time
INSTALL_FIRMWARE_CMD=install_firmware
P_TO_R_INIT_CMD=p_to_r_init
SSH_CMD=ssh
SSH_CMD_EXEC=ssh_exec
STATIC_V4_CMD=:
STATIC_V6_CMD=:
CHECK_SIG_CMD=check_sig
DROP_CACHES=drop_caches
SET_HOSTNAME=hostname
[ -z "$MOUNT_ROOT_RO" ] && MOUNT_ROOT_RO=mount_root_ro_common

# Files
ATLASINIT=$BB_BIN_DIR/atlasinit; export REG_INIT_BIN
NETCONFIG_V4_DEST=/storage/etc/netconfig_v4.sh
NETCONFIG_V6_DEST=/storage/etc/netconfig_v6.sh
KEY_PREFIX=$BASE_DIR/etc/fw-sig-key
RESOLV_CONF_STATIC='/storage/etc/resolv.conf.static'
P_TO_R_INIT_IN=$STATUS_DIR/p_to_r_init.in.vol
SSH_PVT_KEY=$BASE_DIR/etc/probe_key
STATE_FILE=$STATUS_DIR/reginit.vol

FIRMWARE_FETCH_DIR=/storage
FIRMWARE_TARGET_DIR=/storage/etc

# Various files and directories
RESOLV_CONF=/tmp/resolv.conf
STATE_DIR=$BASE_DIR/state
REG_SERVERS=$BIN_DIR/reg_servers.sh  
REG_SERVERS_SOURCE=$BASE_DIR/etc/reg_servers.sh  
DHCPC_PID=$STATUS_DIR/dhcpc-pid	# Cannot be vol, then it will be removed

# Other conf
TELNETD_PORT=2023
DHCP=False
LANINF=br-lan
SSH_OPT=' -C '
ATLASINIT_DEVICE_OPT='-I br-lan'

# Commands

after_passwdset()
{
	# Remount root read-only 
	$MOUNT_ROOT_RO
}
arp()
{
	$BB_SBIN_DIR/arp "$@"
}
check_sig()
{
	file="$1"
	fw_hash=$(sha256sum $file | sed 's/ .*//')
	for i in $KEY_PREFIX-*.pem
	do
		for j in 1 2 3 4 5	# Assume 5 sigs is enough
		do
			grep -q SIGNATURE_APPS$j /home/atlas/status/reg_init_reply.txt ||
				continue
			echo "Checking signature $j for key $i"
			grep SIGNATURE_APPS$j /home/atlas/status/reg_init_reply.txt |
				sed "s/SIGNATURE_APPS$j [^ ]* //" | 
				base64 -d >/tmp/sig.txt

			openssl rsautl -verify -inkey $i -keyform PEM -pubin -in /tmp/sig.txt > /tmp/hash.txt
			if [ $(cat /tmp/hash.txt) == $fw_hash ]
			then
				echo Signature checks out
				return 0
			else
				echo Signature failed, got "$(cat /tmp/hash.txt)", expected $fw_hash
			fi
		done
	done
	echo 'End of check_sig'
	return 1
}
chown_data_dirs()
{
	chown atlas $DATA_DIR $DATA_NEW_DIR $DATA_OUT_DIR $DATA_DIR/out/ooq $DATA_DIR/out/ooq10
}
chown_for_msm()
{
	chown -R atlas $BASE_DIR/crons
	chown -R atlas $BASE_DIR/crons/
	chown -R atlas $BASE_DIR/data
	chown -R atlas $BASE_DIR/data/
}
date()
{
	$BB_BIN_DIR/date "$@"
}
drop_caches()
{
	echo 3 > /proc/sys/vm/drop_caches
}
handle_storage_current_time()
{
	if [ -f /storage/currenttime.txt ]
	then
		ce=$(expr $(cat /storage/currenttime.txt) + 1800)
		if [ ! -n "$ce" ] ||
			expr $(cat $STATUS_DIR/currenttime.txt) '>=' $ce ||
			expr $(cat $STATUS_DIR/currenttime.txt) '<' $ce
		then
			cp $STATUS_DIR/currenttime.txt /storage/currenttime.txt
		fi
	else
		cp $STATUS_DIR/currenttime.txt /storage/currenttime.txt
	fi
}
get_arch()
{
	if [ -f /lib/ar71xx.sh ]
	then
		. /lib/ar71xx.sh
		ar71xx_board_name
	elif [ -f /lib/ramips.sh ]
	then
		sh /lib/ramips.sh
		sed < /tmp/sysinfo/board_name 's/tplink,//'
	elif [ -f  /etc/board.json ] && grep -q '"friendlyarm,nanopi-neo-plus2"' /etc/board.json
	then
		echo 'nanopi-neo-plus2'
	elif [ -f  /etc/board.json ] && grep -q '"cznic,turris-mox"' /etc/board.json
	then
		echo 'turris-mox'
	else
		echo 'unknown board'
		exit 1
	fi
}

hostname()
{
	$BB_BIN_DIR/hostname "$@"
}
kill_dhcpc()
{
	if [ -f $DHCPC_PID ]
	then
		kill -9 `tail -1 $DHCPC_PID`
		rm -f $DHCPC_PID
	fi
}
load_storage_current_time()
{
	if [ -f /storage/currenttime.txt ]
	then
		ce=$(cat /storage/currenttime.txt)
		if [ ! -n "$ce" ] || expr $(date '+%s') '<' $ce
		then
			cp /storage/currenttime.txt $STATUS_DIR/currenttime.txt 
		fi
	fi
}
mount_root_ro_common()
{
	mount -o remount,ro /
}
trigger_manual_upgrade()
{
	if [ -f $DEV_FIRMWARE ] ; then
		# Manual firmware upgrade
		rm -f $STATUS_DIR/reginit.vol
	fi
}
manual_firmware_upgrade()
{
	if [ -f $DEV_FIRMWARE ] ; then
		# Manual firmware upgrade
		install_firmware manual
		reboot
		exit
	fi
}
openwrt_atlas_init()
{
	# Get ethernet address
	get_ether_addr

	while :
	do
		mode=$(cat $MODE_FILE)
		case X$mode in
		Xdev|Xtest|Xprod)
			# Okay
			if [ ! -f $REG_SERVERS ]
			then
				/etc/init.d/ntpd enable
				/etc/init.d/ntpd start
				cp $REG_SERVERS_SOURCE.$mode $REG_SERVERS
				cp $KEY_PREFIX_SOURCE-$mode.pem $KEY_PREFIX-1.pem
			fi
			if [ X$mode = "Xprod" ]
			then
				disable_sshd
			fi
		;;
		*)
			echo "Probe is not configured, mode $mode"
			sos "Imode-$mode"
			sleep 60
			continue
		;;
		esac
		break
	done

	$SET_LEDS_CMD start

	setup_storage

	# Report original boot time for now
	D=`epoch` 
	MSG="RESULT 9000 done $D original boot time"
	echo "$MSG" >> $DATA_NEW_DIR/simpleping
	echo "$MSG"

	# Set time to something in the past.
	date -S -s 946684800
	D=`epoch` 
	MSG="RESULT 9000 done $D safe boot time"
	echo "$MSG" >> $DATA_NEW_DIR/simpleping
	echo "$MSG"

	# Redirect cores to /home/atlas/data
	echo '/home/atlas/data/%e.%p.%s.%t.core' > /proc/sys/kernel/core_pattern

	# Set up for user atlas
	setcap "cap_net_raw=ep cap_sys_time=ep" /home/atlas/bb-13.3/bin/busybox

	$MOUNT_ROOT_RO
}
rptra6()
{
	sudo -u atlas $BB_BIN_DIR/rptra6 "$@"
}

reboot_probe()
{
	reboot
}
static_config()
{
	if [ -f $NETCONFIG_V4_DEST ] ; then
		D=`epoch`
		echo "RESULT 9100 done $D FOUND STATIC CONFIGURATION USING IT" >> $DATA_NEW_DIR/simpleping
		echo "RESULT 9100 done $D FOUND STATIC CONFIGURATION USING IT"
		DHCP=False
		. $NETCONFIG_V4_DEST
		evping_no_check -4 -c 2 $IPV4_GW 
		ARP=`arp -n $IPV4_GW`
		set $ARP
		MAC=$4
		if [ ! -n $MAC -o $MAC == '<incomplete>' ] ; then
			/sbin/route del default
			if [ ! -n $MAC ]; then
				msg="RESULT 9102 done $D DEFAUL NO Gateway in ARP table START DHCP"
			else
				msg="RESULT 9101 done $D DEFAULT GW is incomplete START DHCP"
			fi
			echo "$msg" >> $DATA_NEW_DIR/simpleping
			echo "$msg"
				
			/sbin/udhcpc $dhcpoptions &
			DHCP=Temp
			sleepkick 5
		fi
	else 
		D=`epoch`
		echo "RESULT 9103 done $D DEFAULT USE DHCP" >> $DATA_NEW_DIR/simpleping
		echo "RESULT 9103 done $D DEFAULT USE DHCP" 
		DHCP=True
		/sbin/udhcpc $dhcpoptions &
		sleepkick 5                                 
	fi
}
# We need telnet without SU, for the RPM it is needed with SU.
telnetd()
{
        $BB_BASE_DIR/usr/sbin/telnetd "$@"
}

