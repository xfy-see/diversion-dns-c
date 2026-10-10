# SPDX-License-Identifier: GPL-3.0-or-later
# Opt-in package experiment. Stage with scripts/stage-openwrt-package.py.
include $(TOPDIR)/rules.mk

PKG_NAME:=diversion-dns-c-lite
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=lto gc-sections

include $(INCLUDE_DIR)/package.mk

# MIPS32 needs helpers for the existing 64-bit atomic counter. Keep the small
# SDK helper archive local; do not introduce a libatomic.so runtime dependency.
ifeq ($(ARCH),mipsel)
  DIVERSION_EXTRA_LIBS:=-Wl,-Bstatic -latomic -Wl,-Bdynamic
endif
# CI builds these with exactly the package compiler/flags. They are never installed.
DIVERSION_TEST_NAMES:=dns_test cache_domain_test fixed_config_test fixed_engine_test nft_netlink_test domain_driver nft_cli_driver
DIVERSION_TEST_TARGETS=$(if $(filter 1,$(DIVERSION_BUILD_TESTS)),$(addprefix $(PKG_BUILD_DIR)/build-openwrt/tests/,$(DIVERSION_TEST_NAMES)))

define Package/diversion-dns-c-lite
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=Experimental fixed DNS splitter with libc regex
  DEPENDS:=+libpthread
  URL:=https://github.com/xfy-see/diversion-dns-c
endef

define Package/diversion-dns-c-lite/description
  Opt-in dynamically linked POSIX-lite fixed splitter. Restricted ASCII regex
  grammar; see REGEX-POSIX-LITE.md before use. No service or configuration is
  installed or enabled. The portable static release remains separate.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/src/. $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/c \
		CC="$(TARGET_CC)" AR="$(TARGET_AR)" \
		BUILD="$(PKG_BUILD_DIR)/build-openwrt" REGEX_BACKEND=posix-lite \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -Os -std=c11 -Wall -Wextra -Wpedantic -pthread -UNDEBUG" \
		LDFLAGS="$(TARGET_LDFLAGS) -static-libgcc -Wl,-z,stack-size=1048576" \
		EXTRA_LDLIBS="$(DIVERSION_EXTRA_LIBS)" \
		all $(DIVERSION_TEST_TARGETS)
endef

define Package/diversion-dns-c-lite/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build-openwrt/mosdns-c $(1)/usr/sbin/diversion-dns-c-lite
endef

$(eval $(call BuildPackage,diversion-dns-c-lite))
