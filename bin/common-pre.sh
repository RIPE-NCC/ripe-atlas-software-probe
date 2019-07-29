# Shell variables that are needed in both ATLAS and reginit.sh
# These variables are set before the platform dependend scripts are run.

# Defaults, override if necessary
: ${BASE_DIR:=/home/atlas}	# BASE_DIR if not already set
SSH_DIR=$BASE_DIR/.ssh
BIN_DIR=$BASE_DIR/bin
STATUS_DIR=$BASE_DIR/status
STATE_DIR=$BASE_DIR/state
RUN_DIR=$BASE_DIR/run
CON_KEEP_PID=con_keep_pid.vol
RESOLV_CONF_STATIC='/etc/resolv.conf.static'
NETWORK_V4_STATIC_INFO=$STATUS_DIR/network_v4_static_info.txt
NETWORK_V4_INFO=$STATUS_DIR/network_v4_info.txt
NETWORK_V6_STATIC_INFO=$STATUS_DIR/network_v6_static_info.txt
REG_INIT_REPLY=$STATUS_DIR/reg_init_reply.txt
