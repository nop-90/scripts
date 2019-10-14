#!/bin/bash
function interface {
    # Input
    nft insert rule filter input iif $1 tcp dport 53 accept
    nft insert rule filter input iif $1 udp dport 53 accept
    nft insert rule filter input iif $1 udp dport 67 accept
    nft insert rule filter input iif $1 tcp dport 445 accept
    # Forward
    nft insert rule filter forward iif $1 oif $1 accept
    nft insert rule filter forward ip saddr $2 iif $1 accept
    nft insert rule filter forward ip daddr $2 oif $1 ct state established,related accept
    # Nat
    nft add rule nat postrouting ip saddr $2 ip daddr 224.0.0.0/24 return
    nft add rule nat postrouting ip saddr $2 ip daddr 255.255.255.255/32 return
    nft add rule nat postrouting ip saddr $2 ip daddr != $2 masquerade
}

function interface-int {
    # Input
    nft insert rule filter input iif $1 tcp dport 53 accept
    nft insert rule filter input iif $1 udp dport 53 accept
    nft insert rule filter input iif $1 udp dport 67 accept
    nft insert rule filter input iif $1 tcp dport 445 accept
    # Forward
    nft insert rule filter forward iif $1 oif $1 accept
    nft insert rule filter forward ip saddr $2 iif $1 accept
    nft insert rule filter forward ip daddr $2 oif $1 ct state established,related accept
}

function interface-iso {
    # Input
    nft insert rule filter input iif $1 tcp dport 53 accept
    nft insert rule filter input iif $1 udp dport 53 accept
    nft insert rule filter input iif $1 tcp dport 67 accept
    nft insert rule filter input iif $1 tcp dport 445 accept
}

function external {
    ip link add virbrext-dum address 52:54:00:05:29:68 type dummy
    brctl addbr virbrext
    brctl stp virbrext on
    brctl addif virbrext virbrext-dum
    ip a add 192.168.122.1/24 dev virbrext broadcast 192.168.122.255
    interface virbrext 192.168.122.0/24
    ip l set virbrext up
    dnsmasq --conf-file=/var/lib/dnsmasq/virbrext/dnsmasq.conf --pid-file=/var/run/dnsmasq/virbrext.pid
}

function internal {
    ip link add virbrint-dum address 52:54:00:ed:49:78 type dummy
    brctl addbr virbrint
    brctl stp virbrint on
    brctl addif virbrint virbrint-dum
    ip a add 192.168.100.1/24 dev virbrint broadcast 192.168.100.255
    interface-int virbrint 192.168.100.0/24
    ip l set virbrint up
    dnsmasq --conf-file=/var/lib/dnsmasq/virbrint/dnsmasq.conf --pid-file=/var/run/dnsmasq/virbrint.pid
}

function isolated {
    ip link add virbriso-dum address 52:54:00:9a:14:75 type dummy
    brctl addbr virbriso
    brctl stp virbriso on
    brctl addif virbriso virbriso-dum
    ip a add 192.168.99.1/24 dev virbriso broadcast 192.168.99.255
    interface-iso virbriso 192.168.99.0/24
    ip l set virbriso up
    dnsmasq --conf-file=/var/lib/dnsmasq/virbriso/dnsmasq.conf --pid-file=/var/run/dnsmasq/virbriso.pid
}
if [ ! -d "/var/run/dnsmasq" ]; then
    mkdir /var/run/dnsmasq
fi
sleep 3

sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.conf.all.forwarding=1

if [ "$1" == "int" ]; then
    internal
elif [ "$1" == "iso" ]; then
    isolated
else
    external
fi
