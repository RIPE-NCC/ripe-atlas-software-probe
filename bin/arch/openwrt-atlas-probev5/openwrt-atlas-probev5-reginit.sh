. /home/atlas/bin/common-pre.sh

# Commands
CHECK_FOR_NEW_KERNEL_CMD=:

# Files
KERNEL_STATE_DIR=/home/atlas/state

. $BIN_DIR/arch/openwrt/openwrt-common.sh
. $BIN_DIR/arch/openwrt-atlas-probev5/openwrt-atlas-probev5-common.sh
. $BIN_DIR/arch/linux/linux-functions.sh

TMP_FW=/storage/turrisos-mvebu-cortexa53-device-cznic-mox-rootfs.tar.gz

clean_snapshots()
{
	MOUNT_POINT=/mnt/.snapshots

	mount -o remount,rw /
	mkdir -p "$MOUNT_POINT"
	mount /dev/mmcblk1p1 "$MOUNT_POINT"

	btrfs subvolume list / |
		grep '@[0-9][0-9]*$' |
		sed 's/.*\(@[0-9]*\)$/\1/' |
		head -3 |
		while read a
		do
			btrfs subvolume delete "$MOUNT_POINT/$a/storage"
			btrfs subvolume delete "$MOUNT_POINT/$a"
		done
	umount "$MOUNT_POINT"
}

install_firmware()
{
	fw=$1

	# Remove some old snapshots
	clean_snapshots

	# Just in case they are still mounted from a previous run
	umount /mnt/.snapshots

	# Remount root read-write
	mount -o remount,rw /

	# Find out what device we are running on
	currdev=$(sed < /proc/cmdline 's/.*root=\([^ ]*\).*/\1/')
	#case X"$currdev" in
	#X/dev/mmcblk2p2)
	#	target_partition=p3
	#;;
	#X/dev/mmcblk2p3)
	#	target_partition=p2
	#;;
	#*)
	#	# Weird
	#	exit
	#;;
	#esac
	#target_dev_prefix=/dev/mmcblk2
	#target_dev="$target_dev_prefix$target_partition"
	# Create filesystem
	#mke2fs -F -t ext4 $target_dev
	# Mount filesystem
	#mkdir -p /altroot
	#mount $target_dev /altroot
	if [ "$fw" = manual ]
	then
		# Uncompress image. Note that DEV_FIRMWARE has a wildcard
		mv $DEV_FIRMWARE "$TMP_FW"
	else
		# Uncompress image
		bunzip2 -cd $1 > $TMP_FW
	fi
	# Create new snapshot
	schnapps import -f "$TMP_FW"

	rm -f "$TMP_FW"

	# Mount new snapshot
	mkdir -p /mnt/.snapshots
	mount /dev/mmcblk1p1 /mnt/.snapshots

	TMP_ROOT=/mnt/.snapshots/@factory

	# Copy probe's private key
	cp $SSH_PVT_KEY $TMP_ROOT/$SSH_PVT_KEY
	cp /etc/config/network $TMP_ROOT/etc/config/network
	cp /home/atlas/state/mode $TMP_ROOT/home/atlas/state/mode

	# Copy host ssh keys (for dev and test access)
	for f in /etc/ssh/ssh_host_*
	do
		if [ -f "$f" ]
		then
			cp $f $TMP_ROOT"$f"
		fi
	done

	cp /etc/config/network $TMP_ROOT/etc/config
	cp /etc/config/system $TMP_ROOT/etc/config

	umount /mnt/.snapshots

	# Record current time
	date +%s >/home/atlas/status/currenttime.txt

	schnapps rollback factory
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
