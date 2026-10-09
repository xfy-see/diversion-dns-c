# SPDX-License-Identifier: GPL-3.0-or-later
CC ?= cc
AR ?= ar
BUILD ?= ../.build/c-native-no-unicode-no-jit
# Build this pinned dependency with scripts/build-native-pcre2.py first.
# Never silently select a system PCRE2 with different Unicode/JIT features.
PCRE2_PREFIX ?= ../.build/pcre2-8-no-unicode-no-jit
PCRE2_CFLAGS ?= -I$(PCRE2_PREFIX)/include
PCRE2_LIB ?= $(PCRE2_PREFIX)/lib/libpcre2-8.a
CPPFLAGS += -Iinclude -Ivendor/libyaml/include $(PCRE2_CFLAGS) -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -pthread
LDLIBS += $(PCRE2_LIB) -pthread
ifeq ($(SANITIZE),1)
CFLAGS += -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif
LIBSRC = coremain/engine.c pkg/dns.c pkg/upstream.c pkg/domain.c pkg/util.c plugin/cache.c plugin/nftset.c
YAMLSRC = $(wildcard vendor/libyaml/src/*.c)
LIBOBJ = $(patsubst %.c,$(BUILD)/%.o,$(LIBSRC) $(YAMLSRC))
APPOBJ = $(BUILD)/main.o $(BUILD)/pkg/server.o
TESTS = dns_test cache_domain_test engine_test plan_regression_test nft_netlink_test

.PHONY: all test unit integration clean
all: $(BUILD)/mosdns-c
$(BUILD)/mosdns-c: $(APPOBJ) $(BUILD)/libmosdns-c.a $(wildcard $(PCRE2_LIB))
	$(CC) $(LDFLAGS) -o $@ $(APPOBJ) $(BUILD)/libmosdns-c.a $(LDLIBS)
$(BUILD)/libmosdns-c.a: $(LIBOBJ)
	$(AR) rcs $@ $^
$(BUILD)/vendor/libyaml/src/%.o: vendor/libyaml/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(filter-out -Werror,$(CFLAGS)) -DYAML_VERSION_STRING='"0.2.5"' -DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2 -DYAML_VERSION_PATCH=5 -MMD -MP -c $< -o $@
$(BUILD)/%.o: %.c include/mosdns.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/tests/%: tests/%.c $(BUILD)/libmosdns-c.a $(wildcard $(PCRE2_LIB))
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(BUILD)/libmosdns-c.a $(LDLIBS) -o $@
unit: $(addprefix $(BUILD)/tests/,$(TESTS)) $(BUILD)/tests/domain_driver
	$(BUILD)/tests/dns_test
	$(BUILD)/tests/cache_domain_test
	$(BUILD)/tests/engine_test
	$(BUILD)/tests/plan_regression_test
	$(BUILD)/tests/nft_netlink_test
	python3 tests/domain_fixture.py $(BUILD)/tests/domain_driver
integration: $(BUILD)/mosdns-c
	python3 tests/integration.py $(BUILD)/mosdns-c
	python3 tests/plan_integration.py $(BUILD)/mosdns-c
test: unit integration
clean:
	rm -f $(BUILD)/mosdns-c $(BUILD)/libmosdns-c.a $(LIBOBJ) $(APPOBJ) $(addprefix $(BUILD)/tests/,$(TESTS)) $(BUILD)/tests/domain_driver
-include $(LIBOBJ:.o=.d) $(APPOBJ:.o=.d)
