# SPDX-License-Identifier: GPL-3.0-or-later
.DEFAULT_GOAL := all
CC ?= cc
AR ?= ar
# Separate output trees prevent accidental object reuse across backend modes.
REGEX_BACKEND ?= pcre2
ifeq ($(REGEX_BACKEND),pcre2)
BUILD ?= ../.build/c-native-no-unicode-no-jit
else ifeq ($(REGEX_BACKEND),posix-lite)
BUILD ?= ../.build/c-native-posix-lite
else
$(error REGEX_BACKEND must be pcre2 or posix-lite)
endif
# Build this pinned dependency with scripts/build-native-pcre2.py first.
# Never silently select a system PCRE2 with different Unicode/JIT features.
PCRE2_PREFIX ?= ../.build/pcre2-8-no-unicode-no-jit
PCRE2_CFLAGS ?= -I$(PCRE2_PREFIX)/include
PCRE2_LIB ?= $(PCRE2_PREFIX)/lib/libpcre2-8.a
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
ifeq ($(REGEX_BACKEND),pcre2)
CPPFLAGS += $(PCRE2_CFLAGS)
REGEX_LIB = $(PCRE2_LIB)
else
CPPFLAGS += -DMD_REGEX_POSIX=1
REGEX_LIB =
endif
CFLAGS ?= -Os -flto -g
LDFLAGS ?= -flto
CFLAGS += -UNDEBUG -std=c11 -Wall -Wextra -Wpedantic -Werror -pthread
EXTRA_LDLIBS ?=
LDLIBS += $(REGEX_LIB) -pthread $(EXTRA_LDLIBS)
ifeq ($(SANITIZE),1)
CFLAGS += -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif
LIBSRC = coremain/engine.c pkg/dns.c pkg/upstream.c pkg/domain.c pkg/util.c plugin/cache.c plugin/nftset.c
LIBOBJ = $(patsubst %.c,$(BUILD)/%.o,$(LIBSRC))
APPOBJ = $(BUILD)/main.o $(BUILD)/pkg/server.o
TESTS = dns_test cache_domain_test fixed_config_test fixed_engine_test nft_netlink_test
DRIVERS = domain_driver nft_cli_driver

.PHONY: all test unit integration clean check-backend
# Explicit BUILD overrides also cannot silently mix objects across backends.
check-backend:
	@mkdir -p $(BUILD)
	@if test -f $(BUILD)/regex-backend && test "$$(cat $(BUILD)/regex-backend)" != "$(REGEX_BACKEND)"; then echo "backend changed: use a fresh BUILD directory" >&2; exit 1; fi
	@if ! test -f $(BUILD)/regex-backend; then \
	  if test -n "$$(find $(BUILD) -mindepth 1 -print -quit)"; then echo "unmarked nonempty BUILD directory: use a fresh directory" >&2; exit 1; fi; \
	  printf '%s\n' "$(REGEX_BACKEND)" > $(BUILD)/regex-backend; \
	fi
all: $(BUILD)/mosdns-c
$(BUILD)/mosdns-c: $(APPOBJ) $(BUILD)/libmosdns-c.a $(wildcard $(REGEX_LIB))
	$(CC) $(LDFLAGS) -o $@ $(APPOBJ) $(BUILD)/libmosdns-c.a $(LDLIBS)
$(BUILD)/libmosdns-c.a: $(LIBOBJ)
	@rm -f $@
	$(AR) rcs $@ $^
$(BUILD)/%.o: %.c include/mosdns.h | check-backend
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/tests/%: tests/%.c $(BUILD)/libmosdns-c.a $(wildcard $(REGEX_LIB)) | check-backend
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(BUILD)/libmosdns-c.a $(LDLIBS) -o $@
$(BUILD)/tests/cache_domain_test: tests/regex_posix_profile.h tests/regex_concurrency.h tests/regex_budget_profile.h
ifeq ($(shell uname -s),Darwin)
$(BUILD)/tests/nft_cli_driver: CPPFLAGS += -Itests/nft_uapi
endif
$(BUILD)/tests/nft_cli_driver: tests/nft_cli_driver.c pkg/dns.c plugin/nftset.c plugin/nft_fast.h include/mosdns.h include/nft_netlink.h | check-backend
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) tests/nft_cli_driver.c pkg/dns.c -pthread $(EXTRA_LDLIBS) -o $@
unit: $(addprefix $(BUILD)/tests/,$(TESTS) $(DRIVERS))
	$(BUILD)/tests/dns_test
	$(BUILD)/tests/cache_domain_test
	$(BUILD)/tests/fixed_config_test
	$(BUILD)/tests/fixed_engine_test
	$(BUILD)/tests/nft_netlink_test
	python3 tests/domain_fixture.py $(BUILD)/tests/domain_driver --backend $(REGEX_BACKEND)
	python3 tests/nft_cli_test.py --driver $(BUILD)/tests/nft_cli_driver --output $(BUILD)/nft-cli-$$(date +%s)-$$$$ $(if $(filter 1,$(SANITIZE)),--sanitize)
integration: $(BUILD)/mosdns-c
	python3 tests/fixed_integration.py $(BUILD)/mosdns-c
test: unit integration
clean:
	rm -f $(BUILD)/mosdns-c $(BUILD)/libmosdns-c.a $(LIBOBJ) $(APPOBJ) $(addprefix $(BUILD)/tests/,$(TESTS) $(DRIVERS))
-include $(LIBOBJ:.o=.d) $(APPOBJ:.o=.d)
