. /usr/local/atlas/bin/common-pre.sh

# Directories

# Commands
CHECK_FOR_NEW_KERNEL_CMD=:
INSTALL_FIRMWARE_CMD=:
P_TO_R_INIT_CMD=p_to_r_init
SSH_CMD=ssh
SSH_CMD_EXEC=ssh_exec

# Options
SSH_OPT=''

NETCONFIG_V4_DEST=$HOME/etc/netconfig_v4.sh
NETCONFIG_V6_DEST=$HOME/etc/netconfig_v6.sh
P_TO_R_INIT_IN=$STATUS_DIR/p_to_r_init.in.vol

if [ ! -n "$STATE_FILE" ] ; then
	echo "called without state file as argument"
	STATE_FILE=$STATUS_DIR/reginit.vol
fi

. /usr/local/atlas/bin/arch/centos-atlas-anchor/centos-atlas-anchor-common.sh
. /usr/local/atlas/bin/arch/linux/linux-functions.sh

get_arch()
{
	echo "centos"
}

p_to_r_init()
{
	{
		echo P_TO_R_INIT
		echo TOKEN_SPECS `get_arch` 1000 `cat $STATE_DIR/FIRMWARE_APPS_VERSION`
		echo REASON_FOR_REGISTRATION $1
	} | tee $P_TO_R_INIT_IN
}
