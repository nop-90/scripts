#!/bin/bash
sudo rtl_entropy -e -f 77M -b
sudo rngd -r /var/run/rtl_entropy.fifo -W95% -b
