#!/bin/bash
if [ $# -eq 0 ]
then
    echo "Usage : wireshark_rasp.sh [interface name]"
else
    wireshark -k -i <(ssh alarm@rasp.nop-90.net -i ~/.ssh/id_rsa_temp -p25566 "dumpcap -P -i $1 -w - -f 'not tcp port 25566'")
fi
