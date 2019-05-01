. /home/atlas/bin/common-pre.sh
. /home/atlas/bin/arch/openwrt-atlas-probev3/openwrt-tplink-common.sh

# Commands
CHECK_RO_USB=check_ro_usb

# Various files and directories
DEV_FIRMWARE=/storage/etc/openwrt-ar71xx-atlas-rootfs.tar; export DEV_FIRMWARE
MODE_FILE=/mnt/oldroot/home/atlas/state/mode
KEY_PREFIX_SOURCE=$BASE_DIR/etc/2017-11-07

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
		mount -o remount,ro /
	;;
	esac

	# Make sure the one on the built-in flash is set to dynamic
	case "X$(uci -c /mnt/oldroot/etc/config get network.lan.proto)" in
	Xdhcp)
		# Nothing to do
	;;
	*)
		echo Enabling dhcp in /mnt/oldroot/etc/config/network
		uci -c /mnt/oldroot/etc/config set network.lan.proto=dhcp
		uci -c /mnt/oldroot/etc/config commit
	;;
	esac

	kill_dhcpc

	# Bounce interface to get RAs to be sent
	echo Bouncing br-lan.
	ifconfig br-lan down up

	/sbin/ifconfig lo 127.0.0.1
	/sbin/route add -net 127.0.0.0 netmask 255.0.0.0 lo

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

check_ro_usb()
{
	if [ -b /dev/sda -a "$(cat /sys/dev/block/8:0/ro)" = 1 ]
	then
		sos "IUSB-READONLY"
	fi
	#if [ -b /dev/sda -a "$(cat /sys/dev/block/8:0/ro)" = 0 ]
	#then
	#	sos "IUSB-READWRITE"
	#fi
}

setup_storage()
{
	# Setup sda1
	cryptsetup create --verbose --debug --key-file /mnt/oldroot/home/atlas/etc/sda2.key sda1 /dev/sda1
	e2fsck -p /dev/mapper/sda1 ||
	{
		echo 'e2fsck failed, creating new fs'
		mke2fs -F -t ext4 /dev/mapper/sda1
	}
	mkdir /storage
	mount /dev/mapper/sda1 /storage
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
}

disable_ssh()
{
	# This should no longer be necessary
	/etc/init.d/dropbear disable
	/etc/init.d/dropbear stop
	# Also remove from built-in flash
	rm -f /mnt/oldroot/etc/rc.d/*dropbear
}

openwrt_atlas_init
