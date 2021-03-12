. /usr/local/atlas/bin/common-pre.sh

# Commands
MANUAL_UPGRADE_CMD=:
TRY_UPGRADE_CMD=:
FINDPID_SSH_CMD=findpid_ssh
KILL_PERDS_CMD=kill_perds
KILL_SSH_CMD=kill_ssh
KILL_TELNETD_CMD=kill_telnetd
MOUNT_FS_CMD=:
SETUP_NETWORK_CMD=:
NTPCLIENT_CMD=:
SU_CMD="sudo -u atlasmsm"
CHOWN_FOR_MSM=:
CHMOD_FOR_MSM=chmod_for_msm
SET_HOSTNAME=:

# For OpenWRT we need telnetd to run as root.
telnetd()
{
	$SU_CMD $BB_BASE_DIR/usr/sbin/telnetd "$@"
}

# Various files and directories
: ${HOME:=/home/atlas}; export HOME	# Set HOME if it isn't set
RESOLV_CONF=/etc/resolv.conf
MODE_FILE=$BASE_DIR/state/mode

# Other conf
DHCP=False
do_rxtxrpt=yes

. /usr/local/atlas/bin/arch/centos-atlas-anchor/centos-atlas-anchor-common.sh

# Directories
STATE_DIR=$RPM_BASE_DIR/state; export STATE_DIR
BB_BASE_DIR=$RPM_BASE_DIR/bb-13.3; export BB_BASE_DIR
BB_BIN_DIR=$BB_BASE_DIR/bin; export BB_BIN_DIR

# Files
REG_SERVERS_SOURCE=$RPM_ETC_DIR/reg_servers.sh  

. /usr/local/atlas/bin/arch/linux/linux-functions.sh

chmod_for_msm()
{
	chmod -R g+rwX $BASE_DIR/data
}

# Get ethernet address
get_ether_addr

# Set SOS_ID to the hash of the public key
export SOS_ID="H$(hash_ssh_pubkey $BASE_DIR/etc/probe_key.pub)"

# Try to link in FIRMWARE_APPS_VERSION
ln -sf $RPM_BASE_DIR/state/FIRMWARE_APPS_VERSION $BASE_DIR/state/FIRMWARE_APPS_VERSION

while :
do
	mode=$(cat $MODE_FILE)
	case X$mode in
	Xdev|Xtest|Xprod)
		# Okay
		if [ ! -f $REG_SERVERS ]
		then
			mkdir -p $BASE_DIR/bin
			cp $REG_SERVERS_SOURCE.$mode $REG_SERVERS
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
