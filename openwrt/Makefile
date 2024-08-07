include $(TOPDIR)/rules.mk

PKG_NAME:=ripe-atlas-probe
PKG_VERSION:=$(shell cat $(CURDIR)/$(SOURCE)/../VERSION)
PKG_RELEASE:=1
PKG_LICENSE:=GPL
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Michel Stam <mstam@ripe.net>
PKG_FIXUP=autoreconf
PKG_INSTALL:=1
PRB_TYPE:=$(if $(CONFIG_RIPE_ATLAS_PROBE_TYPE_V3),openwrt-atlas-probev3,$(if $(CONFIG_RIPE_ATLAS_PROBE_TYPE_V4),openwrt-atlas-probev4,$(if $(CONFIG_RIPE_ATLAS_PROBE_TYPE_V5),openwrt-atlas-probev5,generic)))

ATLAS_USER=ripe-atlas
ATLAS_GROUP=ripe-atlas
ATLAS_MEAS=ripe-atlas-measurement
PROBE_FW_KEYS=

include $(INCLUDE_DIR)/package.mk

define Package/ripe-atlas/Default
	TITLE:=RIPE Atlas
	SECTION:=net
	CATEGORY:=Network
	URL:=https://atlas.ripe.net/
endef

CONFIGURE_ARGS+= \
	--with-probe-type=$(PRB_TYPE) \
	--with-user=$(ATLAS_USER) \
	--with-group=$(ATLAS_GROUP) \
	--with-measurement-user=$(ATLAS_MEAS) \
	--disable-systemd \
	--disable-setcap-install \
	--disable-chown

define Package/ripe-atlas/Default/description
RIPE Atlas is the RIPE NCC's main Internet data
collection system. It is a global network of
devices, called probes and anchors, that
actively measure Internet connectivity. Anyone
can access this data via Internet traffic maps,
streaming data visualisations, and an API.
RIPE Atlas users can also perform customised
measurements to gain valuable data about their
own networks.
endef

define Build/Prepare
	$(CP) $(patsubst %/openwrt,%,$(TOPDIR)/$(SOURCE))/. $(PKG_BUILD_DIR)
endef


define Package/ripe-atlas-common
	$(call Package/ripe-atlas/Default)
	TITLE+=(common files)
	USERID:=$(ATLAS_USER):$(ATLAS_GROUP) $(ATLAS_MEAS):$(ATLAS_GROUP)
	DEPENDS+= \
                  +e2fsprogs \
                  +jsonfilter \
                  +openssh-client \
                  +openssh-keygen \
                  +libopenssl \
		  +@OPENSSL_WITH_DEPRECATED \
	          +@BUSYBOX_CONFIG_HOSTNAME \
	          +@BUSYBOX_CONFIG_KILL \
	          +@BUSYBOX_CONFIG_KILLALL \
	          +@BUSYBOX_CONFIG_PS \
	          +@BUSYBOX_CONFIG_SED \
	          +@BUSYBOX_CONFIG_TAR \
                  +!PACKAGE_ntpd:chrony \
		  +!BUSYBOX_CONFIG_BUNZIP2:bzip2
	CONFLICTS:=atlasmsm \
	           atlasprobe \
	           atlas_extra_v3 \
	           atlas_extra_v4 \
	           atlas_extra_v5 \
	           atlas-sw-probe \
	           atlas-sw-probe-rpc

ifneq ($(CONFIG_RIPE_ATLAS_PROBE_TYPE_V5),)
	DEPENDS+= \
	          +btrfs
endif
endef

define Package/ripe-atlas-common/conffiles
/etc/ripe-atlas/mode
endef

define Package/ripe-atlas-common/description
RIPE Atlas (common files)

$(call Package/ripe-atlas/Default/description)
endef

define LinkApplet
	$(LN) busybox $(1)/usr/lib/ripe-atlas/measurement/$(2)
endef

ifneq ($(CONFIG_RIPE_ATLAS_PROBE_TYPE_V3),)
	PROBE_FW_KEYS += \
		2017-11-07-dev.pem \
		2017-11-07-prod.pem \
		2017-11-07-test.pem
endif
ifneq ($(CONFIG_RIPE_ATLAS_PROBE_TYPE_V4),)
	PROBE_FW_KEYS += \
		2018-04-23-dev.pem \
		2018-04-23-prod.pem \
		2018-04-23-test.pem
endif
ifneq ($(CONFIG_RIPE_ATLAS_PROBE_TYPE_V5),)
	PROBE_FW_KEYS += \
		2021-02-02-dev.pem \
		2021-02-02-prod.pem \
		2021-02-02-test.pem
endif

define Package/ripe-atlas-common/install
	$(INSTALL_DIR) \
		$(1)/etc/init.d \
		$(1)/etc/uci-defaults \
		$(1)/usr/lib/ripe-atlas/measurement \
		$(1)/usr/lib/ripe-atlas/scripts \
		$(1)/usr/share/ripe-atlas \
		$(1)/usr/sbin
	$(INSTALL_BIN) -t \
		$(1)/usr/lib/ripe-atlas/scripts \
		$(foreach script, \
			array.lib.sh \
			atlas_log.lib.sh \
			class.lib.sh \
			common-pre.sh \
			common.sh \
			config.sh \
			$(PRB_TYPE)-ATLAS.sh \
			$(PRB_TYPE)-common.sh \
			$(PRB_TYPE)-reginit.sh \
			json.lib.sh \
			linux-functions.sh \
			paths.lib.sh \
			reg_servers.sh.dev \
			reg_servers.sh.test \
			reginit.sh \
			resolvconf \
			support.lib.sh, \
			$(PKG_INSTALL_DIR)/usr/lib/ripe-atlas/scripts/$(script))
	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/usr/lib/ripe-atlas/measurement/busybox \
		$(1)/usr/lib/ripe-atlas/measurement/busybox
	$(INSTALL_BIN) \
		$(PKG_INSTALL_DIR)/usr/sbin/ripe-atlas \
		$(1)/usr/sbin/ripe-atlas
	$(INSTALL_DATA) -t \
		$(1)/usr/share/ripe-atlas \
		$(foreach file, \
			FIRMWARE_APPS_VERSION \
			measurement.conf \
			$(PROBE_FW_KEYS), \
			$(PKG_INSTALL_DIR)/usr/share/ripe-atlas/$(file))
	$(INSTALL_BIN) files/ripe-atlas.init $(1)/etc/init.d/ripe-atlas
	$(INSTALL_BIN) files/ripe-atlas.uci-defaults $(1)/etc/uci-defaults/60_ripe-atlas
	$(INSTALL_DATA) files/capabilities.json $(1)/usr/share/ripe-atlas/capabilities.json
	$(call LinkApplet,$(1),atlasinit)
	$(call LinkApplet,$(1),buddyinfo)
	$(call LinkApplet,$(1),condmv)
	$(call LinkApplet,$(1),date)
	$(call LinkApplet,$(1),dfrm)
	$(call LinkApplet,$(1),eooqd)
	$(call LinkApplet,$(1),eperd)
	$(call LinkApplet,$(1),evhttpget)
	$(call LinkApplet,$(1),evntp)
	$(call LinkApplet,$(1),evping)
	$(call LinkApplet,$(1),evsslgetcert)
	$(call LinkApplet,$(1),evtdig)
	$(call LinkApplet,$(1),evtraceroute)
	$(call LinkApplet,$(1),httppost)
	$(call LinkApplet,$(1),onlyuptime)
	$(call LinkApplet,$(1),perd)
	$(call LinkApplet,$(1),rchoose)
	$(call LinkApplet,$(1),rptaddrs)
	$(call LinkApplet,$(1),rptra6)
	$(call LinkApplet,$(1),rptuptime)
	$(call LinkApplet,$(1),rxtxrpt)
	$(call LinkApplet,$(1),telnetd)
endef

define Package/ripe-atlas-probe
	$(call Package/ripe-atlas/Default)
	TITLE+=(Software Probe)
	DEPENDS+=+ripe-atlas-common
	VARIANT:=probe
	CONFLICTS+=ripe-atlas-anchor
	MENU:=1
endef

define Package/ripe-atlas-probe/config
	source "$(SOURCE)/Config.in"
endef

define Package/ripe-atlas-probe/description
RIPE Atlas (Software Probe)

$(call Package/ripe-atlas/Default/description)
endef

define Package/ripe-atlas-probe/install
	$(INSTALL_DIR) \
		$(1)/usr/lib/ripe-atlas/scripts \
		$(1)/usr/share/ripe-atlas
	$(INSTALL_DATA) \
		$(PKG_BUILD_DIR)/config/probe/known_hosts.reg \
		$(1)/usr/share/ripe-atlas
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/config/probe/reg_servers.sh.prod \
		$(1)/usr/lib/ripe-atlas/scripts
endef

define Package/ripe-atlas-probe/conffiles
/etc/ripe-atlas/probe_key
/etc/ripe-atlas/probe_key.pub
/etc/config/ripe-atlas
endef

define Package/ripe-atlas-anchor
	$(call Package/ripe-atlas/Default)
	TITLE+=(Anchor)
	DEPENDS+=+ripe-atlas-common
	VARIANT:=anchor
	PROVIDES+=ripe-atlas-probe
	MENU:=1
endef

define Package/ripe-atlas-anchor/config
	source "$(SOURCE)/Config.in"
endef

define Package/ripe-atlas-anchor/description
RIPE Atlas (Anchor)

$(call Package/ripe-atlas/Default/description)
endef

define Package/ripe-atlas-anchor/install
	$(INSTALL_DIR) \
		$(1)/usr/lib/ripe-atlas/scripts \
		$(1)/usr/share/ripe-atlas
	$(INSTALL_DATA) \
		$(PKG_BUILD_DIR)/config/anchor/known_hosts.reg \
		$(1)/usr/share/ripe-atlas
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/config/anchor/reg_servers.sh.prod \
		$(1)/usr/lib/ripe-atlas/scripts
endef

define Package/ripe-atlas-anchor/conffiles
/etc/ripe-atlas/probe_key
/etc/ripe-atlas/probe_key.pub
/etc/config/ripe-atlas
endef

$(eval $(call BuildPackage,ripe-atlas-common))
$(eval $(call BuildPackage,ripe-atlas-anchor))
$(eval $(call BuildPackage,ripe-atlas-probe))
