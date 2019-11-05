. /home/atlas/bin/common-pre.sh
. /home/atlas/bin/arch/openwrt-atlas-probev3/openwrt-atlas-probev3-common.sh

# Commands
CHECK_FOR_NEW_KERNEL_CMD=check_for_new_kernel

# Files
KERNEL_STATE_DIR=/mnt/oldroot/home/atlas/state
USB_DEVICES=/sys/kernel/debug/usb/devices

. $BIN_DIR/arch/openwrt/openwrt-common.sh
. $BIN_DIR/arch/linux/linux-functions.sh

install_firmware()
{
	fw=$1
	# Just in case they are still mounted from a previous run
	umount /mnt/extroot

	# Remount root read-write
	mount -o remount,rw /

	# Find out what device we are running on
	currdev=$(uci -c /mnt/oldroot/etc/config/ get fstab.@mount[0].device)
	case X"$currdev" in
	X/dev/mapper/sda2)
		target_dev=/dev/mapper/sda3
	;;
	X/dev/mapper/sda3)
		target_dev=/dev/mapper/sda2
	;;
	*)
		# Weird
		exit
	;;
	esac
	# Create filesystem
	mke2fs -F -t ext4 $target_dev
	# Mount filesystem
	mkdir -p /mnt/extroot
	mount $target_dev /mnt/extroot
	if [ "$fw" = manual ]
	then
		# Move root filesystem
		mv /storage/etc/openwrt-ar71xx-atlas-rootfs.tar /mnt/extroot
	else
		# Extract root filesystem tar.
		bunzip2 -dc $1 | (cd /mnt/extroot && tar xvf - openwrt-ar71xx-atlas-rootfs.tar)
	fi
	# Extract root filesystem
	(cd /mnt/extroot && tar oxvf openwrt-ar71xx-atlas-rootfs.tar)
	# Copy probe's private key
	cp $SSH_PVT_KEY /mnt/extroot/$SSH_PVT_KEY
	cp /etc/config/network /mnt/extroot/etc/config/network
	#cp /etc/resolv.conf.static /mnt/extroot/etc/resolv.conf.static
	#cp /home/atlas/etc/netconfig_v4.sh /mnt/extroot/home/atlas/etc/netconfig_v4.sh
	#cp /home/atlas/etc/netconfig_v6.sh /mnt/extroot/home/atlas/etc/netconfig_v6.sh
	#mkdir -p /home/atlas/status
	#cp /home/atlas/status/netconfig_v4.vol /mnt/extroot/home/atlas/status/netconfig_v4.vol
	#cp /home/atlas/status/netconfig_v6.vol /mnt/extroot/home/atlas/status/netconfig_v6.vol

	# Change the root filesystem. Also force network to be dhcp. Otherwise
	# A change to static may get picked up.
	uci -c /mnt/oldroot/etc/config/ set fstab.@mount[0].device=$target_dev
	uci -c /mnt/oldroot/etc/config set network.lan.proto=dhcp
	uci -c /mnt/oldroot/etc/config/ commit

	# Make optional changes to the new filesystem after switching to the
	# new partition. This way, if any of the changes fails we still boot
	# the new image.

	# Record current time
	date +%s >/mnt/extroot/home/atlas/status/currenttime.txt
}

prepare_for_kernel()
{
	# Kernel image should in / already. Copy the reg. server output.
	cp $CON_INIT_CONF /
	# Create CON_INIT_CMD 
	sed < $CON_INIT_CONF 's/  */=/' > /con_init_cmd.sh
	cp $REG_INIT_REPLY /

	# Remove $CON_INIT_CMD to trigger going to the registration server
	# after upgrading
	rm -f $STATUS_DIR/$CON_INIT_CONF

	# Switch back to built-in root
	uci -c /mnt/oldroot/etc/config/ set fstab.@mount[0].enabled=0
	uci -c /mnt/oldroot/etc/config/ commit
}

p_to_r_init()
{
	{
		reason="$1"
		echo P_TO_R_INIT
		echo TOKEN_SPECS `get_arch` `cat $KERNEL_STATE_DIR/FIRMWARE_KERNEL_VERSION` `cat $STATE_DIR/FIRMWARE_APPS_VERSION`
		if [ -b /dev/sda ]; then
			vendor=`cat $USB_DEVICES |
				grep Vendor | tail -n +2 |
				sed 's/^P: //'`
			manuf=`cat $USB_DEVICES |
				grep Manufacturer |
				tail -n +2 | sed 's/^S: //'`
			prod=`cat $USB_DEVICES |
				grep Product | tail -n +2 |
				sed 's/^S: //'`
			serial=`cat $USB_DEVICES |
				grep SerialNumber |
				tail -n +2 | sed 's/^S: //'`
			ro=`cat /sys/dev/block/8:0/ro`
			p=`grep 'sda$' /proc/partitions`
			if [ -n "$p" ]
			then
				set $p
				size=$3
			else
				size=unknown
			fi
			echo USB_INFO Size=$size ro=$ro $serial $vendor $manuf $prod
		fi
		echo REASON_FOR_REGISTRATION "$reason"
	} | tee $P_TO_R_INIT_IN
}

check_for_new_kernel()
{
	## check for new kernel
	if [ -n "$FIRMWARE_KERNEL" ] ; then
		FIRMWARE_KERNEL_VERSION_MY=`cat $KERNEL_STATE_DIR/FIRMWARE_KERNEL_VERSION`
		if [ $FIRMWARE_KERNEL_VERSION -gt  $FIRMWARE_KERNEL_VERSION_MY ] ; then
			echo "there is a newer FIRMWARE_KERNEL_VERSION $FIRMWARE_KERNEL_VERSION, current one is $FIRMWARE_KERNEL_VERSION_MY"

			D=`epoch`
			echo "RESULT 9013 done $D $ETHER_SCANNED newer kernel firmware $FIRMWARE_KERNEL_VERSION, currently running $FIRMWARE_KERNEL_VERSION_MY"  >> $DATA_DIR/new/simpleping

			mount -o remount,rw /

			D=`epoch`
			echo "RESULT 9011 done $D $ETHER_SCANNED Starting $SSH_CMD -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST FIRMWARE_KERNEL $FIRMWARE_KERNEL"  >> $DATA_DIR/new/simpleping
			$SSH_CMD $SSH_OPT -i $SSH_PVT_KEY -p $CONTROLLER_1_PORT atlas@$CONTROLLER_1_HOST  "FIRMWARE_KERNEL $FIRMWARE_KERNEL" > /$FIRMWARE_KERNEL 2>$SSH_ERR
			ERR=$?
			if [ $ERR != "0" ] ; then
				D=`epoch`
				echo "RESULT 9011 done $D $ETHER_SCANNED ERR $ERR stderr" `cat $SSH_ERR`  >> $DATA_DIR/new/simpleping
			fi

			echo "check md5 of $FIRMWARE_KERNEL"
			MD5FULL=`md5sum /$FIRMWARE_KERNEL`
			set $MD5FULL
			MD5=$1

			if [ $MD5 ==  $FIRMWARE_KERNEL_CS_COMP ] ; then 
				# the checksums match schedule an upgrade 
				echo "checksums match $MD5 $FIRMWARE_KERNEL_CS_COMP "
				prepare_for_kernel
				echo "rebooting to built-in flash"
				reboot
				exit
			else 
				echo "checksums failed. $FIRMWARE_KERNEL" 
				echo "Ignore upgrade and proceed to Controller for INIT"
			fi
		else
			echo "IGNORE kernel upgrade mine, $FIRMWARE_KERNEL_VERSION_MY,  is newer or the same as $FIRMWARE_KERNEL_VERSION"
		fi
		
	fi
}

manual_firmware_upgrade

