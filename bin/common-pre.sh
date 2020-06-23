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
REG_INIT_REPLY=$STATUS_DIR/reg_init_reply.txt
CONFIG_TXT="$BASE_DIR/state/config.txt"
