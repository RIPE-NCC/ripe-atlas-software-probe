# Files
# Commands

SET_LEDS_CMD=set_leds_nanopi_neo_plus2

# Config
IPV6_INF="br-lan"

set_leds_nanopi_neo_plus2()
{
	state="$1"
	case X"$state" in

	Xkeep-found)
		echo timer > /sys/class/leds/nanopi\:green\:pwr/trigger
	;;
	esac
}
