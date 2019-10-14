#!/bin/bash
function interface {
    # Input
    nft insert rule filter input iif $1 tcp dport 53 accept
    nft insert rule filter input iif $1 udp dport 53 accept
    nft insert rule filter input iif $1 tcp dport 67 accept
    nft insert rule filter input iif $1 udp dport 67 accept
    nft insert rule filter input iif $1 tcp dport 445 accept
    nft insert rule filter input iif $1 udp dport 445 accept
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
    nft insert rule filter input iif $1 tcp dport 67 accept
    nft insert rule filter input iif $1 udp dport 67 accept
    nft insert rule filter input iif $1 tcp dport 445 accept
    nft insert rule filter input iif $1 udp dport 445 accept
    # Forward
    nft insert rule filter forward iif $1 oif $1 accept
    nft insert rule filter forward ip saddr $2 iif $1 accept
    nft insert rule filter forward ip daddr $2 oif $1 ct state established,related accept
}

function external {
    ovs-vsctl add-port br-external wlp2s0
    ifconfig wlp2s0 0
    dhcpcd br-external
    ip a add 192.168.122.1/24 dev br-external
    ip r del default via $1 dev wlp2s0
    ip r del $2 dev wlp2s0
    interface br-external 192.168.122.0/24
    dnsmasq --conf-file=/var/lib/dnsmasq/br-external/dnsmasq.conf --pid-file=/var/run/dnsmasq/br-external.pid
}

function internal {
    ip a add 192.168.100.1/24 dev br-internal
    interface-int br-internal 192.168.100.0/24
    dnsmasq --conf-file=/var/lib/dnsmasq/br-internal/dnsmasq.conf --pid-file=/var/run/dnsmasq/br-internal.pid
}


sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.conf.all.forwarding=1
systemctl start ovsdb-server
systemctl start ovs-vswitchd
if [ ! -d "/var/run/dnsmasq" ]; then
    mkdir /var/run/dnsmasq
fi
sleep 3

if [ "$1" == "int" ]; then
    internal
else
    if [ $# -lt 2 ]; then
        echo "Missing current default route and IP range"
    else
        external $1 $2
    fi
fi
