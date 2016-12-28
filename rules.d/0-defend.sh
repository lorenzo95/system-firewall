#!/bin/sh

#
# Testing by Gero
# Reference: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
#

# we are a router
#echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
# Kernel
#echo '0' > /proc/sys/net/ipv4/ip_forward
#if [ -r /proc/sys/net/ipv4/ip_forward ]; then
#  echo "Disabling IP forwarding"
#  echo "0" > /proc/sys/net/ipv4/ip_forward
#fi
# MAYBE WE SHOULD DO THIS LAST?

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
# Defend against various attacks
#

# Basic INPUT policy:

iptables -A INPUT -i lo -j ACCEPT

#   syn-flooding protection
iptables -N syn-flood
iptables -A INPUT -i $OUTSIDE_IF -p tcp --syn -j syn-flood
iptables -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
iptables -A syn-flood -j DROP

#   make sure NEW tcp connections are SYN packets
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate=NEW -j DROP

#   don't allow your own IP address as input -exploited to flood itself 
#   with it's own packets
iptables -A INPUT -s $OUTSIDE_ADDR -j LOG --log-prefix "fw:spoofoutside:INPUT:drop "
iptables -A INPUT -s $OUTSIDE_ADDR -j DROP 

#   Spoofing Reverse Path Filter attack mitigation
iptables -t raw -I PREROUTING -m rpfilter --invert -j DROP

#   Drop packets with impossible TCP flag combinations before they hit conntrack rules.
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j DROP


#   Drop INVALID state traffic
iptables -A INPUT -m state --state INVALID -j DROP

#   Allow incoming SSH, but limit to 3 connections per min. per IP to prevent brute force attack chatter in logs.
#iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --set --name DEFAULT --rsource
#iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name DEFAULT --rsource -j DROP
#iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT

#   mitigate SSH bruteforce attacks 
# iptables -N IN_SSH
# iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -j IN_SSH
# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 3 --seconds 10 -j DROP
# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 4 --seconds 1800 -j DROP 
# iptables -A IN_SSH -m recent --name sshbf --set -j ACCEPT

# Basic OUTPUT policy:

iptables -A OUTPUT -o lo -j ACCEPT

iptables -A OUTPUT -m state --state INVALID -j DROP
#iptables -A OUTPUT -p icmp -m state --state NEW -m owner --gid-owner root -j ACCEPT
#iptables -A OUTPUT -m state --state NEW -m owner --uid-owner root -j ACCEPT 
#iptables -A OUTPUT -m state --state NEW -m owner --gid-owner root -j ACCEPT


# If NOTRACK is supported, don't pass loopback traffic through conntrack (better performance)
iptables -t raw -A PREROUTING -i lo -j CT

# Basic FORWARD policy:

iptables -A FORWARD -p tcp -m tcp --tcp-flags ALL ALL -j DROP
iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A FORWARD -p tcp -m tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A FORWARD -p tcp -m tcp --tcp-flags ALL NONE -j DROP
iptables -A FORWARD -p icmp -f -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
#iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

exit 0




