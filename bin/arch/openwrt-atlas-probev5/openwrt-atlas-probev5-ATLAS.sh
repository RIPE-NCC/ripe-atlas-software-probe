. /home/atlas/bin/common-pre.sh
. /home/atlas/bin/arch/openwrt-atlas-probev5/openwrt-atlas-probev5-common.sh

# Tell httppost that it should set update the system time 
export HTTPPOST_ALLOW_STIME=true

export do_rxtxrpt=yes

# Commands
CHECK_RO_USB=:
SET_DATE_FROM_CURRENTTIME_TXT=set_date_from_currenttime_txt

# Various files and directories
DEV_FIRMWARE=/storage/etc/turrisos-*-mvebu-cortexa53-device-cznic-mox-rootfs.tar.gz; export DEV_FIRMWARE
MODE_FILE=/home/atlas/state/mode
KEY_PREFIX_SOURCE=$BASE_DIR/etc/2018-04-23

. /home/atlas/bin/arch/openwrt/openwrt-common.sh
. /home/atlas/bin/arch/linux/linux-functions.sh

setup_network()
{
	case "X$(uci get network.lan.proto)" in
	Xstatic)
		# Nothing to do
	;;
	*)
		echo Disabling dhcp in /etc/config/network
		mount -o remount,rw /
		uci set network.lan.proto=static
		# A dummy IP address is required.
		uci set network.lan.ipaddr="10.1.2.3"
		uci commit
		echo before reload
		ifconfig
		echo ===
		/etc/init.d/network reload
		sleep 10	# Reload seems to be asynchronous. Wait a bit
		echo after reload
		ifconfig
		echo ===
		$MOUNT_ROOT_RO
	;;
	esac

	## Make sure the one on the built-in flash is set to dynamic
	#case "X$(uci get network.lan.proto)" in
	#Xdhcp)
	#	# Nothing to do
	#;;
	#*)
	#	echo Enabling dhcp in /etc/config/network
	#	uci set network.lan.proto=dhcp
	#	uci commit
	#;;
	#esac

	kill_dhcpc

	# Bounce interface to get RAs to be sent
	echo Bouncing br-lan.
	#ifconfig br-lan down up

	#/sbin/ifconfig lo 127.0.0.1
	#/sbin/route add -net 127.0.0.0 netmask 255.0.0.0 lo

	if [ -f $RESOLV_CONF_STATIC ] ; then 
		echo "FOUND  $RESOLV_CONF_STATIC copy to $RESOLV_CONF"
		cp $RESOLV_CONF_STATIC $RESOLV_CONF
	fi

	if [ -f $NETCONFIG_V6_DEST ] ; then
		/sbin/ifconfig eth0 0.0.0.0 
		. $NETCONFIG_V6_DEST
	fi 

	if grep PROBE_ID $REG_INIT_REPLY
	then
		probeid=`sed -n '/PROBE_ID/s/.* /-/p' < $REG_INIT_REPLY`
		hostnameoption="-H RIPE-Atlas-Probe$probeid"
	else
		hostnameoption=""
	fi
	dhcpoptions="-i $LANINF -p $DHCPC_PID -t 9999 -T 3 -V RIPE-Atlas-Probe $hostnameoption"

	static_config
}

setup_storage()
{
	btrfs subvolume create /storage
	mount -o subvol=/@/storage /dev/mmcblk1p1 /storage

	#STORAGE_DEV=/dev/mmcblk2p4
	#e2fsck -p $STORAGE_DEV ||
	#{
	#	echo 'e2fsck failed, creating new fs'
	#	mke2fs -F -t ext4 $STORAGE_DEV
	#}
	#mkdir /storage
	#mount $STORAGE_DEV /storage
	mkdir -p /storage/data

	mkdir -p /tmp/data
	mkdir -p /tmp/data/new
	ln -s /storage/data /tmp/data/storage

	mkdir -p /storage/crons

	mkdir -p /tmp/status

	mkdir -p /tmp/run
	mkdir -p /tmp/atlas-run
	chown atlas /tmp/atlas-run

	mkdir -p /storage/etc

	# Older firmware versions have netconfig_v4.sh, netconfig_v6.sh, 
	# and resolv.conf.static in a different location. Try to move
	# them.
	if [ -f /home/atlas/etc/netconfig_v4.sh ]
	then
		mv /home/atlas/etc/netconfig_v4.sh /storage/etc/
	fi
	if [ -f /home/atlas/etc/netconfig_v6.sh ]
	then
		mv /home/atlas/etc/netconfig_v6.sh /storage/etc/
	fi
	if [ -f /etc/resolv.conf.static ]
	then
		mv /etc/resolv.conf.static /storage/etc/
	fi

	rm -f /etc/resolv.conf
	ln -s /tmp/resolv.conf /etc

	mkdir /tmp/root
	rm -fr /root
	ln -s /tmp/root /
	mkdir -p /tmp/root/.ssh
	cp /home/atlas/etc/authorized_keys /tmp/root/.ssh/authorized_keys
}

disable_sshd()
{
	if [ -f /etc/init.d/sshd ]
	then
		/etc/init.d/sshd disable
		/etc/init.d/sshd stop
		# Also remove it
		rm -f /etc/init.d/sshd
		# may be more aggressive
		# opkg remove openssh-server
	fi
}

openwrt_atlas_init
