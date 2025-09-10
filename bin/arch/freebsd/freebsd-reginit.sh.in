if [ -n "$ATLAS_BASE" ]
then
	BASE_DIR="$ATLAS_BASE"
	export ATLAS_BASE
fi

. $ATLAS_SCRIPTS/common-pre.sh

# Directories

# Commands
CHECK_FOR_NEW_KERNEL_CMD=:
INSTALL_FIRMWARE_CMD=:
P_TO_R_INIT_CMD=p_to_r_init
SSH_CMD=ssh
SSH_CMD_EXEC=ssh_exec

# Options
SSH_OPT=''

NETCONFIG_V4_DEST=$ATLAS_SYSCONFDIR/netconfig_v4.sh
NETCONFIG_V6_DEST=$ATLAS_SYSCONFDIR/netconfig_v6.sh
P_TO_R_INIT_IN=$ATLAS_STATUS/p_to_r_init.in.vol

if [ -z "$STATE_FILE" ] ; then
	STATE_FILE=$ATLAS_STATUS/reginit.vol
	echo "Warning: STATE_FILE unset. Setting to -> $STATE_FILE"
fi

. $ATLAS_SCRIPTS/$DEVICE_NAME-common.sh
. $ATLAS_SCRIPTS/freebsd-functions.sh

get_arch()
{
	echo "freebsd"
}

get_sub_arch()
{
	local ID='freebsd'
	local VERSION_ID=$(uname -r | cut -d'-' -f1)
	local ARCH=$(uname -m)
	echo "${ID}/${VERSION_ID}/${ARCH}"
}

p_to_r_init()
{
	{
		echo P_TO_R_INIT
		echo TOKEN_SPECS `get_arch` 1000 `cat $ATLAS_DATADIR/FIRMWARE_APPS_VERSION` `get_sub_arch`
		echo REASON_FOR_REGISTRATION $1
	} | tee $P_TO_R_INIT_IN
}
