cmd_scripts/kconfig/mconf.o := gcc -Wp,-MD,scripts/kconfig/.mconf.o.d  -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer       -c -o scripts/kconfig/mconf.o scripts/kconfig/mconf.c

deps_scripts/kconfig/mconf.o := \
  scripts/kconfig/mconf.c \
    $(wildcard include/config/mode.h) \
    $(wildcard include/config/.h) \
  /usr/include/sys/ioctl.h \
  /usr/include/features.h \
    $(wildcard include/config/c99.h) \
    $(wildcard include/config/c95.h) \
    $(wildcard include/config/ix.h) \
    $(wildcard include/config/ix2.h) \
    $(wildcard include/config/ix199309.h) \
    $(wildcard include/config/ix199506.h) \
    $(wildcard include/config/en.h) \
    $(wildcard include/config/en/extended.h) \
    $(wildcard include/config/x98.h) \
    $(wildcard include/config/en2k.h) \
    $(wildcard include/config/gefile.h) \
    $(wildcard include/config/gefile64.h) \
    $(wildcard include/config/e/offset64.h) \
    $(wildcard include/config/d.h) \
    $(wildcard include/config/c.h) \
    $(wildcard include/config/ile.h) \
    $(wildcard include/config/ntrant.h) \
    $(wildcard include/config/tify/level.h) \
    $(wildcard include/config/i.h) \
    $(wildcard include/config/ern/inlines.h) \
  /usr/include/sys/cdefs.h \
    $(wildcard include/config/espaces.h) \
  /usr/include/bits/wordsize.h \
  /usr/include/gnu/stubs.h \
  /usr/include/gnu/stubs-64.h \
  /usr/include/bits/ioctls.h \
  /usr/include/asm/ioctls.h \
  /usr/include/asm/ioctl.h \
  /usr/include/asm-generic/ioctl.h \
  /usr/include/bits/ioctl-types.h \
  /usr/include/sys/ttydefaults.h \
  /usr/include/sys/wait.h \
  /usr/include/signal.h \
  /usr/include/bits/sigset.h \
  /usr/include/bits/types.h \
  /usr/include/bits/typesizes.h \
  /usr/include/bits/signum.h \
  /usr/include/time.h \
  /usr/include/bits/siginfo.h \
  /usr/include/bits/sigaction.h \
  /usr/include/bits/sigcontext.h \
  /usr/lib/gcc/x86_64-linux-gnu/4.3.2/include/stddef.h \
  /usr/include/bits/sigstack.h \
  /usr/include/bits/pthreadtypes.h \
  /usr/include/bits/sigthread.h \
  /usr/include/sys/resource.h \
  /usr/include/bits/resource.h \
  /usr/include/bits/time.h \
  /usr/include/bits/waitflags.h \
  /usr/include/bits/waitstatus.h \
  /usr/include/endian.h \
  /usr/include/bits/endian.h \
  /usr/include/ctype.h \
  /usr/include/errno.h \
  /usr/include/bits/errno.h \
  /usr/include/linux/errno.h \
  /usr/include/asm/errno.h \
  /usr/include/asm-generic/errno.h \
  /usr/include/asm-generic/errno-base.h \
  /usr/include/fcntl.h \
  /usr/include/bits/fcntl.h \
  /usr/include/sys/types.h \
  /usr/include/sys/select.h \
  /usr/include/bits/select.h \
  /usr/include/sys/sysmacros.h \
  /usr/lib/gcc/x86_64-linux-gnu/4.3.2/include-fixed/limits.h \
  /usr/lib/gcc/x86_64-linux-gnu/4.3.2/include-fixed/syslimits.h \
  /usr/include/limits.h \
  /usr/include/bits/posix1_lim.h \
  /usr/include/bits/local_lim.h \
  /usr/include/linux/limits.h \
  /usr/include/bits/posix2_lim.h \
  /usr/lib/gcc/x86_64-linux-gnu/4.3.2/include/stdarg.h \
  /usr/include/stdlib.h \
  /usr/include/alloca.h \
  /usr/include/string.h \
    $(wildcard include/config/ing/inlines.h) \
  /usr/include/bits/string.h \
  /usr/include/bits/string2.h \
    $(wildcard include/config/ing/arch/strchr.h) \
  /usr/include/termios.h \
  /usr/include/bits/termios.h \
  /usr/include/unistd.h \
  /usr/include/bits/posix_opt.h \
  /usr/include/bits/confname.h \
  /usr/include/getopt.h \
  /usr/include/locale.h \
  /usr/include/bits/locale.h \
  scripts/kconfig/lkc.h \
  scripts/kconfig/expr.h \
  /usr/include/stdio.h \
  /usr/include/libio.h \
    $(wildcard include/config/a.h) \
    $(wildcard include/config/ar/t.h) \
    $(wildcard include/config//io/file.h) \
  /usr/include/_G_config.h \
  /usr/include/wchar.h \
  /usr/include/bits/stdio_lim.h \
  /usr/include/bits/sys_errlist.h \
  /usr/include/bits/stdio.h \
  /usr/lib/gcc/x86_64-linux-gnu/4.3.2/include/stdbool.h \
  /usr/include/libintl.h \
    $(wildcard include/config//gettext.h) \
  scripts/kconfig/lkc_proto.h \

scripts/kconfig/mconf.o: $(deps_scripts/kconfig/mconf.o)

$(deps_scripts/kconfig/mconf.o):
