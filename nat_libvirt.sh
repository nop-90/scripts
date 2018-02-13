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
    nft add rule nat postrouting ip saddr $2 ip daddr != 192.168.122.0/24 masquerade
}

iptables -F -t filter
iptables -F -t nat
iptables -F -t mangle
rmmod iptable_mangle iptable_nat iptable_filter ip_tables
interface virbr0 192.168.122.0/24
#nft insert rule filter input iifname virbr0 accept
#nft insert rule nat postrouting oif wlp2s0 masquerade
#nft insert rule filter forward ct state related,established accept
#nft insert rule filter forward iifname virbr0 accept
