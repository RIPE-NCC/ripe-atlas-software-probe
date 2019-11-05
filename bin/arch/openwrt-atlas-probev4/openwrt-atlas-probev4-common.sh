# Files
# Commands

SET_LEDS_CMD=set_leds_nanopi_neo_plus2

set_leds_nanopi_neo_plus2()
{
	state="$1"
	case X"$state" in

	Xkeep-found)
		echo timer > /sys/class/leds/nanopi\:green\:pwr/trigger
	;;
	esac
}
