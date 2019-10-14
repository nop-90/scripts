#!/bin/bash
rsync -rv --delete-after --progress --no-perms --inplace --omit-dir-times /run/user/1000/gvfs/mtp*/Internal*/* /home/nop-90/Sync/Internal
rsync -rv --size-only --progress --no-perms --inplace --omit-dir-times /run/user/1000/gvfs/mtp*/SanDisk*/DCIM/* /home/nop-90/Sync/DCIM
rsync -rv --delete-after --progress --no-perms --inplace --omit-dir-times /run/user/1000/gvfs/mtp*/SanDisk*/Titanium/* /home/nop-90/Sync/Titanium
