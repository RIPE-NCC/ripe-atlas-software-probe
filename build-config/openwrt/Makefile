include $(TOPDIR)/rules.mk

PKG_NAME:=ripe-atlas-probe
PKG_VERSION:=5080
PKG_RELEASE:=1
PKG_LICENSE:=GPL
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Michel Stam <mstam@ripe.net>
PKG_FIXUP=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ripe-atlas/Default
	TITLE:=RIPE Atlas
	SECTION:=net
	CATEGORY:=Networking
	URL:=https://atlas.ripe.net/
endef

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

define Package/ripe-atlas-common
	$(call Package/ripe-atlas/Default)
	TITLE+=(common files)
	DEPENDS+= \
                  +e2fsprogs \
                  +openssh-client \
	          +@BUSYBOX_CONFIG_HOSTNAME \
	          +@BUSYBOX_CONFIG_KILL \
	          +@BUSYBOX_CONFIG_KILLALL \
	          +@BUSYBOX_CONFIG_PS \
	          +@BUSYBOX_CONFIG_SED \
	          +@BUSYBOX_CONFIG_TAR \
                  +!PACKAGE_ntpd:chrony \
	          +@!PACKAGE_bzip2:BUSYBOX_CONFIG_BUNZIP2

ifneq ($(CONFIG_RIPE_ATLAS_PROBE_TYPE_V3),))
	DEPENDS+= \
	          +screen
endif

ifneq ($(CONFIG_RIPE_ATLAS_PROBE_TYPE_V4),))
	DEPENDS+= \
	          +screen
endif

ifneq ($(CONFIG_RIPE_ATLAS_PROBE_TYPE_V5),))
	DEPENDS+= \
	          +btrfs
	          +screen
endif
endef

define Package/ripe-atlas-common/conffiles
/etc/ripe-atlas/mode
endef

define Package/ripe-atlas-common/description
	RIPE Atlas (common files)

	$(call Package/ripe-atlas/Default/description)
endef

define Package/ripe-atlas-probe
	$(call Package/ripe-atlas/Default)
	TITLE+=(Software Probe)
	DEPENDS+=+ripe-atlas-common
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
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./build-config/openwrt/ripe-atlas.init $(1)/etc/init.d/ripe-atlas
endef

define Package/ripe-atlas-probe/conffiles
/etc/ripe-atlas/probe_key
/etc/ripe-atlas/probe_key.pub
/etc/config/ripe-atlas
endef

$(eval $(call BuildPackage,ripe-atlas-common))
$(eval $(call BuildPackage,ripe-atlas-probe))
