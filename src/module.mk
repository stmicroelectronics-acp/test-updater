# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

all: CXX_BINARY(st-touch-fw-updater)

CXX_BINARY(st-touch-fw-updater): src/st_fw_updater.o

clean: CLEAN(CXX_BINARY(st-touch-fw-updater))
