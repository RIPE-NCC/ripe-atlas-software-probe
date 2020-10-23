# Files
# Commands

SET_LEDS_CMD=set_leds_mox
BUDDYINFO=do_buddyinfo
MOUNT_ROOT_RO=mount_root_ro

# Config
IPV6_INF="br-lan"

# Files
LED=/sys/devices/platform/leds/leds/red

mount_root_ro()
{
	mount -o remount,ro /
	mount -o remount,rw /storage
}
set_leds_mox()
{
	state="$1"

	echo timer > $LED/trigger

	case X"$state" in
	Xstart)
		echo 50 > $LED/delay_on
		echo 500 > $LED/delay_off
	;;
	Xnet-try)
		echo 200 > $LED/delay_on
		echo 200 > $LED/delay_off
	;;
	Xnet-ok)
		echo 1000 > $LED/delay_on
		echo 1000 > $LED/delay_off
	;;
	Xnet-fail)
		echo 100 > $LED/delay_on
		echo 100 > $LED/delay_off
	;;
	Xreg-init)
		echo 300 > $LED/delay_on
		echo 1000 > $LED/delay_off
	;;
	Xreginit-fail)
		echo 100 > $LED/delay_on
		echo 1000 > $LED/delay_off
	;;
	Xctrl-init)
		echo 500 > $LED/delay_on
		echo 1000 > $LED/delay_off
	;;
	Xkeep-start)
		echo 500 > $LED/delay_on
		echo 2000 > $LED/delay_off
	;;
	Xkeep-found)
		echo 2000 > $LED/delay_on
		echo 200 > $LED/delay_off
	;;
	*)
		echo nothing for state "'$state'"
	;;
	esac
}
