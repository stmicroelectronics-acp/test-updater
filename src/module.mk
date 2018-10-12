# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

PC_DEPS = libchrome-$(BASE_VER)
PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
PC_LIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))
LDLIBS += $(PC_LIBS)

CFLAGS += $(PC_CFLAGS)
CPPFLAGS += $(PC_CFLAGS)

all: CXX_BINARY(st-updater)

CXX_BINARY(st-updater): src/st_fw_updater.o

clean: CLEAN(CXX_BINARY(st-updater))
