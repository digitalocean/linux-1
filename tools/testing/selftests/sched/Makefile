# SPDX-License-Identifier: GPL-2.0+

ifneq ($(shell $(CC) --version 2>&1 | head -n 1 | grep clang),)
CLANG_FLAGS += -no-integrated-as
endif

CFLAGS += -O2 -Wall -g -I./ -I../../../../usr/include/  -Wl,-rpath=./ \
	  $(CLANG_FLAGS)
LDLIBS += -lpthread

TEST_GEN_FILES := test_coresched
TEST_PROGS := test_coresched

include ../lib.mk
