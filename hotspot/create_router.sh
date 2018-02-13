nmcli r wifi off
rfkill unblock wlan
nft insert rule filter input udp dport \{53, 67, 68\} ip saddr 192.168.0.0/24 accept
nft insert rule filter input tcp dport \{http, https, 587, 993\} ip saddr 192.168.0.0/24 accept
ifconfig wlp2s0 192.168.0.50/24 up
sleep 1
dnsmasq -C dnsmasq-eth.conf
nft insert rule nat postrouting oif enp3s0 masquerade
nft add rule filter forward ct state related,established accept
nft add rule filter forward iifname wlp2s0 oifname enp3s0 accept

sysctl -w net.ipv4.ip_forword=1
hostapd wifi-eth.conf
killall dnsmasq
ip addr del 192.168.0.50/24 dev wlp2s0
