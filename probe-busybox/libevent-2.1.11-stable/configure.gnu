#!/bin/sh
exec "${0%.gnu}" --disable-shared --enable-static --disable-libevent-install --disable-samples "$@"
