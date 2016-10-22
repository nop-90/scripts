#!/bin/bash
wpa_supplicant -Dnl80211 -c /etc/p2p.conf -i wlp5s0 -B
ip addr add 192.168.0.50/24 dev p2p-wlp5s0-0
systemctl start dnsmasq
