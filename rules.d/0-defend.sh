#!/bin/sh

#
# Testing by Gero
# Reference: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
#

# Enable broadcast echo Protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable Source Routed Packets
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

# Enable TCP SYN Cookie Protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP Redirect Acceptance
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects

# Don't send Redirect Messages
echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects

# Drop Spoofed Packets coming in on an interface where responses
# would result in the reply going out a different interface.
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

# Log packets with impossible addresses.
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians

# Be verbose on dynamic ip-addresses  (not needed in case of static IP)
echo 2 > /proc/sys/net/ipv4/ip_dynaddr

# Disable Explicit Congestion Notification
# Too many routers are still ignorant
echo 0 > /proc/sys/net/ipv4/tcp_ecn

# Ignore bogus responses to broadcast frames
echo '1' > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# allow pinging us. Disable by setting to '1'
echo '0' > /proc/sys/net/ipv4/icmp_echo_ignore_all





#
# Basic INPUT policy:
#

#   Create banned-all list based on specified ports
ipset -N ipset-banned-exempt hash:net
ipset add ipset-banned-exempt 192.168.1.0/24
ipset add ipset-banned-exempt 192.168.1.1
ipset add ipset-banned-exempt 192.168.1.5
ipset add ipset-banned-exempt 10.0.3.0/24

ipset -N ipset-banned-all hash:net

iptables -A INPUT -i lo -j ACCEPT -m comment --comment "Accept Loopback traffic"
iptables -A INPUT -d 127.0.0.0/8 -j REJECT -m comment --comment "deny all 127.x traffic not using lo"

#   Identify port scanning
iptables -A INPUT -i $OUTSIDE_IF -m psd --psd-weight-threshold 15 --psd-hi-ports-weight 3 -j SET --add-set ipset-banned-all src

#   syn-flooding protection
iptables -N CHAIN-SYN-FLOOD
iptables -A INPUT -i $OUTSIDE_IF -p tcp --syn -j CHAIN-SYN-FLOOD -m comment --comment "Jump to syn-flood Chain"
iptables -A CHAIN-SYN-FLOOD -m limit --limit 1/s --limit-burst 4 -j RETURN
iptables -A CHAIN-SYN-FLOOD -j DROP

#   don't allow your own IP address as input -exploited to flood itself with it's own packets
iptables -A INPUT -s $OUTSIDE_ADDR -j DROP -m comment --comment "Drop spoofed outside source IP"

#   DROP PACKETS WITH INCOMING FRAGMENTS.
iptables -A INPUT -f -j DROP -m comment --comment "Drop Fragments"

#   Allow incoming SSH, but limit to 3 connections per min. per IP to prevent brute force attack chatter in logs.
iptables -N CHAIN-SSH-BANNED 
iptables -A INPUT -i $OUTSIDE_IF -p tcp -m tcp --dport 22 -m set ! --match-set ipset-banned-exempt src -j CHAIN-SSH-BANNED -m comment --comment "Jump to ssh chain"
#iptables -A CHAIN-SSH-BANNED -m state --state NEW -m geoip ! --src-cc CA -m tcp -p tcp --dport 22 -j DROP
iptables -A CHAIN-SSH-BANNED -p tcp -m tcp --dport 22 -m state --state NEW -m recent --set --name DEFAULT --rsource
iptables -A CHAIN-SSH-BANNED -p tcp -m tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name DEFAULT --rsource -j DROP
iptables -A CHAIN-SSH-BANNED -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -A CHAIN-SSH-BANNED -j RETURN



# Basic OUTPUT policy:

iptables -A OUTPUT -o lo -j ACCEPT -m comment --comment "Accept Loopback traffic"
#iptables -A OUTPUT -p icmp -m state --state NEW -m owner --gid-owner root -j ACCEPT
#iptables -A OUTPUT -m conntrack --ctstate=NEW -m owner --uid-owner root -j ACCEPT 
#iptables -A OUTPUT -m conntrack --ctstate=NEW -m owner --gid-owner root -j ACCEPT



#
# Basic FORWARD policy:
#



#
# Log invalid packets separately
#
iptables -N CHAIN-INVALID
iptables -A INPUT -m state --state INVALID -j CHAIN-INVALID -m comment --comment "Jump to invalid Chain"
iptables -A FORWARD -m state --state INVALID -j CHAIN-INVALID -m comment --comment "Jump to invalid Chain"
iptables -A OUTPUT -m state --state INVALID -j CHAIN-INVALID -m comment --comment "Jump to invalid Chain"
iptables -A CHAIN-INVALID -j LOG -m limit --limit 5/min --limit-burst 8  --log-level 3 --log-prefix "fw:ip:invalid "
iptables -A CHAIN-INVALID -j DROP
iptables -A CHAIN-INVALID -j RETURN



#
#   Setup MANGLE
#

#   Block Uncommon MSS Values
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate=NEW -m tcpmss ! --mss 536:65535 -j DROP

#   Drop TCP packets that are new and are not SYN
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

#   Block packets with bogus TCP flags
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

#   Cliff Honeypot chain
iptables -N CHAIN-ADD-BANNED -t mangle
iptables -A PREROUTING -t mangle -i $OUTSIDE_IF -m conntrack --ctstate=NEW -m set ! --match-set ipset-banned-exempt src -j CHAIN-ADD-BANNED
iptables -A CHAIN-ADD-BANNED -t mangle -p tcp -m multiport --dports  22:23,445,8200:65535,1433:1434,3389 -m state --state NEW  -j SET --add-set ipset-banned-all src
iptables -A CHAIN-ADD-BANNED -t mangle -p udp -m multiport --dports  135:139,5060:5068 -m state --state NEW  -j SET --add-set ipset-banned-all src
iptables -A CHAIN-ADD-BANNED -t mangle -j RETURN

#
#   Setup RAW
#

#  If NOTRACK is supported, don't pass loopback traffic through conntrack (better performance)
iptables -t raw -A PREROUTING -i lo -j CT -m comment --comment "Don't track loopback connections"

#   Spoofing Reverse Path Filter attack mitigation
iptables -t raw -A PREROUTING -m rpfilter --invert -j DROP -m comment --comment "RPF Filter"

iptables -N CHAIN-DROP-BANNED -t raw
iptables -A PREROUTING -i $OUTSIDE_IF -t raw -p tcp -m set ! --match-set ipset-banned-exempt src -j CHAIN-DROP-BANNED
iptables -A PREROUTING -i $OUTSIDE_IF -t raw -p udp -m set ! --match-set ipset-banned-exempt src -j CHAIN-DROP-BANNED
iptables -A CHAIN-DROP-BANNED -t raw -p tcp -m set --match-set ipset-banned-all src -j DROP
iptables -A CHAIN-DROP-BANNED -t raw -p udp -m set --match-set ipset-banned-all src -j DROP 
iptables -A CHAIN-DROP-BANNED -t raw -j RETURN


#   Setup IPSET rfc list
#ipset -N ipset-rfc1918 hash:net
#ipset add ipset-rfc1918 224.0.0.0/3 
#ipset add ipset-rfc1918 169.254.0.0/16 
#ipset add ipset-rfc1918 172.16.0.0/12
#ipset add ipset-rfc1918 192.0.2.0/24
#ipset add ipset-rfc1918 192.168.0.0/16
#ipset add ipset-rfc1918 10.0.0.0/8
#ipset add ipset-rfc1918 0.0.0.0/8
#ipset add ipset-rfc1918 240.0.0.0/5
#ipset add ipset-rfc1918 127.0.0.0/8

exit 0




