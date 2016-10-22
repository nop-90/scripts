#!/bin/bash
ifconfig enp6s0 up
vde_switch -tap tap0 -daemon -mod 660 -group users
brctl addbr vbr0
brctl addif vbr0 enp6s0
brctl addif vbr0 tap0
dhcpcd vbr0
