# atlas-fw-updater
Touchscreen Controller FW Updater for Atlas Chromebook

## how to build
- clone this repo inside `/src/third_party/st-updater`
- create a file `st-updater-9999.ebuild` in `/src/third_party/chromiumos-overlay/sys-apps/st-updater` with the following content:
```
# Copyright 2017 The Chromium OS Authors. All rights reserved.
# Distributed under the terms of the GNU General Public License v2

EAPI=5

CROS_WORKON_PROJECT="chromiumos/third_party/st-updater"

inherit cros-workon libchrome udev user

DESCRIPTION="A tool to update ST firmware on B50 from Chromium OS."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/st-updater"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND=""

RDEPEND="${DEPEND}"

src_configure() {
	cros-workon_src_configure
}

src_install() {
	dosbin st-updater
}

pkg_preinst() {
	enewuser cfm-firmware-updaters
	enewgroup cfm-firmware-updaters
}
```
- enter the cros_sdk
- cd to `~/trunk/src/scripts` then execute the command `emerge-${BOARD} st-updater` (BOARD=atlas in our case)

## how to deploy to the target machine
- make sure development machine and target machine are on the same network 
- execute `cros deploy [target machine IP] st-updater`

now the `st-updater` binary will be in `/usr/sbin`


