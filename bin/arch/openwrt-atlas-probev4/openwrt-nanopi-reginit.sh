. /home/atlas/bin/common-pre.sh

# Commands
CHECK_FOR_NEW_KERNEL_CMD=:

# Files
KERNEL_STATE_DIR=/home/atlas/state

. $BIN_DIR/arch/openwrt/openwrt-common.sh
. $BIN_DIR/arch/openwrt-atlas-probev4/openwrt-nanopi-common.sh
. $BIN_DIR/arch/linux/linux-functions.sh

install_firmware()
{
	fw=$1
	# Just in case they are still mounted from a previous run
	umount /altroot

	# Remount root read-write
	mount -o remount,rw /

	# Find out what device we are running on
	currdev=$(sed < /proc/cmdline 's/.*root=\([^ ]*\).*/\1/')
	case X"$currdev" in
	X/dev/mmcblk2p2)
		target_partition=p3
	;;
	X/dev/mmcblk2p3)
		target_partition=p2
	;;
	*)
		# Weird
		exit
	;;
	esac
	target_dev_prefix=/dev/mmcblk2
	target_dev="$target_dev_prefix$target_partition"
	# Create filesystem
	mke2fs -F -t ext4 $target_dev
	# Mount filesystem
	mkdir -p /altroot
	mount $target_dev /altroot
	if [ "$fw" = manual ]
	then
		# Move root filesystem
		mv "$DEV_FIRMWARE" /altroot
	else
		# Uncompress image
		bunzip2 -cd $1 > /altroot/openwrt-sunxi-cortexa53-atlas-rootfs.tar
	fi
	# Extract root filesystem
	(cd /altroot && tar oxvf openwrt-sunxi-cortexa53-atlas-rootfs.tar)
	# Copy probe's private key
	cp $SSH_PVT_KEY /altroot/$SSH_PVT_KEY
	cp /etc/config/network /altroot/etc/config/network
	cp /home/atlas/state/mode /altroot/home/atlas/state/mode

	# Copy host ssh keys (for dev and test access)
	for f in /etc/ssh/ssh_host_*
	do
		if [ -f "$f" ]
		then
			cp $f /altroot"$f"
		fi
	done

	# Change the root filesystem. Also force network to be dhcp. Otherwise
	# A change to static may get picked up.
	uci set fstab.@mount[0].device=$target_dev
	uci set network.lan.proto=dhcp
	uci commit

	mount "$target_dev_prefix"p1 /mnt

	# Switch to new filesystem
	cp /altroot/boot/uImage /mnt/uImage-$target_partition
	cp /altroot/boot/dtb /mnt/dtb-$target_partition
	cp /altroot/boot/sun50i-h5-nanopi-neo-plus2-boot-emmc-$target_partition.scr /mnt/boot.scr.new
	mv /mnt/boot.scr.new /mnt/boot.scr

	# Record current time
	date +%s >/home/atlas/status/currenttime.txt
}

p_to_r_init()
{
	{
		reason="$1"
		echo P_TO_R_INIT
		echo TOKEN_SPECS `get_arch` `uname -r` `cat $STATE_DIR/FIRMWARE_APPS_VERSION`
		echo REASON_FOR_REGISTRATION "$reason"
	} | tee $P_TO_R_INIT_IN
}

manual_firmware_upgrade
