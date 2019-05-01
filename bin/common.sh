# Shell variables that are needed in both ATLAS and reginit.sh

DATA_DIR=$BASE_DIR/data
DATA_NEW_DIR=$DATA_DIR/new
DATA_OUT_DIR=$DATA_DIR/out
[ -z "$STATE_DIR" ] && STATE_DIR=$BASE_DIR/state
LOW_MEM_T=256
LOW_DISK_LIMIT=600
SSH_ERR=$STATUS_DIR/ssh_err.txt
[ -z "$KNOWN_HOSTS_REG" ] && KNOWN_HOSTS_REG=$BASE_DIR/etc/known_hosts.reg
FORCE_REG=$STATUS_DIR/force_reg.txt
NETCONFIG_V4_VOL=$STATUS_DIR/netconfig_v4.vol
[ -z "$NETCONFIG_V4_DEST" ] && NETCONFIG_V4_DEST=/etc/netconfig_v4.sh
NETCONFIG_V6_VOL=$STATUS_DIR/netconfig_v6.vol
[ -z "$NETCONFIG_V6_DEST" ] && NETCONFIG_V6_DEST=/etc/netconfig_v6.sh
[ -z "$FIRMWARE_FETCH_DIR" ] && FIRMWARE_FETCH_DIR=$BASE_DIR
[ -z "$FIRMWARE_TARGET_DIR" ] && FIRMWARE_TARGET_DIR=$BASE_DIR/status
