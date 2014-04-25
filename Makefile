#
# Copyright (C) 2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=iwterator
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_MAINTAINER:=Marco Porsch <marco.porsch@posteo.de>

include $(INCLUDE_DIR)/package.mk

define Package/iwterator
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=wireless
  TITLE:=iwterator
  DEPENDS:= +libnl-tiny @(!TARGET_avr32||BROKEN)
endef

define Package/iwterator/description
  Example for Wi-Fi stats collection using netlink
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -rf ./src $(PKG_BUILD_DIR)/
endef

CONFIGURE_PATH:=src

MAKE_PATH:=src

TARGET_CPPFLAGS:= \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	$(TARGET_CPPFLAGS) \
	-DCONFIG_LIBNL20 \
	-D_GNU_SOURCE

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS)" \
	NL1FOUND="" NL2FOUND=Y \
	NLLIBNAME="libnl-tiny" \
	LIBS="-lm -lnl-tiny" \
	V=1

define Package/iwterator/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/iwterator $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,iwterator))
