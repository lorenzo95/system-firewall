#!/bin/sh
#
# iptables configuration for "straker"
#

echo "$(date) - ** Starting firewall configuration..."

PATH=/sbin:/usr/bin:/bin:/usr/local/bin

DIR=`dirname $0`

PATH=$DIR:$PATH
export PATH

#
# Sanity checks
#
if [ ! -d $DIR/rules.d ]
then
	echo "$(date) - $0: no such directory: $DIR/rules.d" >&1
	exit 1
fi

#
# Configuration
#

getip() {
    ip addr show $1 | grep -Po 'inet \K[\d.]+'
}

getnet() {
    ip route | grep  $1 | grep -Po '^[1-2]\S*'
}

#---------------------------#
# BPI-R1 VLAN configuration #
#---------------------------#
#
# port ordering (view from front):
# [ 2 1 0 4 ] [ 3 ]
# [ eth0.101 eth0.102 eth0.103 eth0.104 ] [ eth0.201 ]
#

export OUTSIDE_IF=eth0.201
export OUTSIDE_NET=0.0.0.0/0
export OUTSIDE_ADDR=$(getip $OUTSIDE_IF)

echo "$(date) - Outside interface $OUTSIDE_IF in network $OUTSIDE_NET has address $OUTSIDE_ADDR"

export INSIDE_IF=eth0.101
export INSIDE_ADDR=$(getip $INSIDE_IF)
export INSIDE_NET=$(getnet $INSIDE_IF)

echo "$(date) - Inside interface $INSIDE_IF in network $INSIDE_NET has address $INSIDE_ADDR"

export DMZ_IF=eth0.104
export DMZ_ADDR=$(getip $DMZ_IF)
export DMZ_NET=$(getnet $DMZ_IF)

echo "$(date) - DMZ interface $DMZ_IF in network $DMZ_NET has address $DMZ_ADDR"

if [ -z "$OUTSIDE_ADDR" ]
then
	echo "WARNING: cannot determine external IP address"
fi


############################################################################

export FROM_INSIDE="-i $INSIDE_IF -s $INSIDE_NET"
export FROM_OUTSIDE="-i $OUTSIDE_IF -s $OUTSIDE_NET"
export FROM_DMZ="-i $DMZ_IF -s $DMZ_NET"
export TO_INSIDE="-o $INSIDE_IF -d $INSIDE_NET"
export TO_OUTSIDE="-o $OUTSIDE_IF -d $OUTSIDE_NET"
export TO_DMZ="-o $DMZ_IF -d $DMZ_NET"

modprobe iptable_nat
modprobe ip_conntrack
modprobe ip_conntrack_ftp
modprobe ip_nat_ftp

. functions.sh

#
# Set default policies and initial blocking rules
#

# Disable Forwarding
if [ -r /proc/sys/net/ipv4/ip_forward ]; then
  echo "$(date) - Disabling IP forwarding"
  echo "0" > /proc/sys/net/ipv4/ip_forward
fi

# set the default policies
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# clear the current configuration

# -F for Flush the selected chain (all the chains in the table if none is given). 
# This is equivalent to deleting all the rules one by one. 
iptables -F
iptables -F -t nat

# -Z for Zero the packet and byte counters in all chains
iptables -Z
iptables -Z -t nat

# -X for Delete the optional user-defined chain specified. 
# If no argument is given, it will attempt to delete every non-builtin chain in the table. 
iptables -X

# add blocking entries at the front of the chains
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
iptables -A FORWARD -j DROP

#Dropping all ipv6 traffic
echo "$(date) - I see no need for ipv6 support"
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP

#for r in $DIR/rules.d/*.sh
#do
#	echo "running $r..."
#	$r
#done




#
#
#

$DIR/rules.d/0-defend.sh
$DIR/rules.d/1-firewall.sh
$DIR/rules.d/2-icmp.sh
$DIR/rules.d/3-outgoing.sh



#
#
#



# just in case...
accept_from_inside tcp ssh
accept_from_outside tcp ssh

#
# Drop broadcast traffic from the inside before logging
#
iptables -A INPUT -p tcp -i $INSIDE_IF -d 192.168.13.255/32 -j DROP
iptables -A INPUT -p tcp -i $INSIDE_IF -d 255.255.255.255/32 -j DROP

iptables -A INPUT -p udp -i $INSIDE_IF -d 192.168.13.255/32 -j DROP
iptables -A INPUT -p udp -i $INSIDE_IF -d 255.255.255.255/32 -j DROP

iptables -A INPUT -p igmp -i $INSIDE_IF -d 224.0.0.1/32 -j DROP

iptables -A INPUT -p udp -i $OUTSIDE_IF -d 255.255.255.255/32 -j DROP
iptables -A INPUT -p udp -i $OUTSIDE_IF -d 192.168.1.255/32 -j DROP


#
# Log invalid packets separately
#
iptables -N invalid
iptables -A INPUT -m state --state INVALID -j invalid
iptables -A FORWARD -m state --state INVALID -j invalid
iptables -A invalid -j LOG -m limit --limit 1/s --limit-burst 4  --log-level 3 --log-prefix "fw:ip:invalid "
iptables -A invalid -j DROP
iptables -A invalid -j RETURN

#
# Log anything else
#
iptables -A INPUT -j LOG -m limit --limit 1/s --limit-burst 4  --log-level 3 --log-prefix "fw:ip:INPUT:drop "
iptables -A OUTPUT -j LOG -m limit --limit 1/s --limit-burst 4  --log-level 3 --log-prefix "fw:ip:OUTPUT:drop "
iptables -A FORWARD -j LOG -m limit --limit 1/s --limit-burst 4  --log-level 3 --log-prefix "fw:ip:FORWARD:drop "

# XXX: for debugging
### iptables -A INPUT -j REJECT
### iptables -A OUTPUT -j REJECT
### iptables -A FORWARD -j REJECT

# remove the blocking entries at the front of the chains
iptables -D INPUT 1
iptables -D OUTPUT 1
iptables -D FORWARD 1



# Enable Forwarding
if [ -r /proc/sys/net/ipv4/ip_forward ]; then
  echo "$(date) - Enabling IP forwarding"
  echo "1" > /proc/sys/net/ipv4/ip_forward
fi

echo "$(date) - ** Firewall configuration complete."

echo "$(date) - ###################################" 	>>/var/log/kern.log
echo "$(date) - ***Firewall reset..."			>>/var/log/kern.log
echo "$(date) - ###################################"	>>/var/log/kern.log

iptables -L -v
exit 0
