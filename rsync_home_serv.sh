#!/bin/bash
notify-send 'Backup script' 'Start backing up /home' --icon=dialog-information
rsync -e "ssh" --progress --ignore-errors --delete-after --exclude-from=/home/nop-90/scripts/rsync-exclude.txt -rav /home/nop-90/{.*,*} rsync@node:/external2/home
if [ $? -eq 0 ]; then
    notify-send 'Backup script' 'Backup finished with non-zero status' --icon=dialog-warning
else
    notify-send 'Backup script' 'Backup finished with zero status' --icon=dialog-information
fi
