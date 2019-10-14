#!/bin/bash
rsync -avHe ssh ~/Sync/Commun/* alarm@rasp:/home/alarm/Sync
