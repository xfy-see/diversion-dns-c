# SPDX-License-Identifier: GPL-3.0-or-later
CC ?= cc
AR ?= ar
BUILD ?= ../.build/c-native-no-unicode-no-jit
# Build this pinned dependency with scripts/build-native-pcre2.py first.
# Never silently select a system PCRE2 with different Unicode/JIT features.
PCRE2_PREFIX ?= ../.build/pcre2-8-no-unicode-no-jit
PCRE2_CFLAGS ?= -I$(PCRE2_PREFIX)/include
PCRE2_LIB ?= $(PCRE2_PREFIX)/lib/libpcre2-8.a
CPPFLAGS += -Iinclude $(PCRE2_CFLAGS) -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -pthread
LDLIBS += $(PCRE2_LIB) -pthread
ifeq ($(SANITIZE),1)
CFLAGS += -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif
LIBSRC = coremain/engine.c pkg/dns.c pkg/upstream.c pkg/domain.c pkg/util.c plugin/cache.c plugin/nftset.c
LIBOBJ = $(patsubst %.c,$(BUILD)/%.o,$(LIBSRC))
APPOBJ = $(BUILD)/main.o $(BUILD)/pkg/server.o
TESTS = dns_test cache_domain_test fixed_config_test fixed_engine_test nft_netlink_test
DRIVERS = domain_driver nft_cli_driver

.PHONY: all test unit integration clean
all: $(BUILD)/mosdns-c
$(BUILD)/mosdns-c: $(APPOBJ) $(BUILD)/libmosdns-c.a $(wildcard $(PCRE2_LIB))
	$(CC) $(LDFLAGS) -o $@ $(APPOBJ) $(BUILD)/libmosdns-c.a $(LDLIBS)
$(BUILD)/libmosdns-c.a: $(LIBOBJ)
	@rm -f $@
	$(AR) rcs $@ $^
$(BUILD)/%.o: %.c include/mosdns.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/tests/%: tests/%.c $(BUILD)/libmosdns-c.a $(wildcard $(PCRE2_LIB))
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(BUILD)/libmosdns-c.a $(LDLIBS) -o $@
ifeq ($(shell uname -s),Darwin)
$(BUILD)/tests/nft_cli_driver: CPPFLAGS += -Itests/nft_uapi
endif
$(BUILD)/tests/nft_cli_driver: tests/nft_cli_driver.c pkg/dns.c plugin/nftset.c include/mosdns.h include/nft_netlink.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) tests/nft_cli_driver.c pkg/dns.c -pthread -o $@
unit: $(addprefix $(BUILD)/tests/,$(TESTS) $(DRIVERS))
	$(BUILD)/tests/dns_test
	$(BUILD)/tests/cache_domain_test
	$(BUILD)/tests/fixed_config_test
	$(BUILD)/tests/fixed_engine_test
	$(BUILD)/tests/nft_netlink_test
	python3 tests/domain_fixture.py $(BUILD)/tests/domain_driver
	python3 tests/nft_cli_test.py --driver $(BUILD)/tests/nft_cli_driver --output $(BUILD)/nft-cli-$$(date +%s)-$$$$ $(if $(filter 1,$(SANITIZE)),--sanitize)
integration: $(BUILD)/mosdns-c
	python3 tests/fixed_integration.py $(BUILD)/mosdns-c
test: unit integration
clean:
	rm -f $(BUILD)/mosdns-c $(BUILD)/libmosdns-c.a $(LIBOBJ) $(APPOBJ) $(addprefix $(BUILD)/tests/,$(TESTS) $(DRIVERS))
-include $(LIBOBJ:.o=.d) $(APPOBJ:.o=.d)
