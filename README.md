# atlas-fw-updater
Touchscreen Controller FW Updater for Atlas Chromebook

## how to build
- clone this repo inside `/src/third_party/st-updater`
- move the `st-updater-9999.ebuild` file in `/src/third_party/chromiumos-overlay/sys-apps/st-updater`
- enter the cros_sdk
- cd to `~/trunk/src/scripts` then execute the command `emerge-${BOARD} st-updater` (BOARD=atlas in our case)

## how to deploy to the target machine
- make sure development machine and target machine are on the same network 
- execute `cros deploy [target machine IP] st-updater`

now the `st-updater` binary will be in `/usr/sbin`


