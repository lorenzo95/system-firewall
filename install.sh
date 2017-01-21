#!/bin/bash
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
	echo "[+] $0: no such directory: $DIR/rules.d" >&1
	exit 1
fi

#
# Configuration
#

getip() {
    ip addr show $1 | grep -Po 'inet \K[\d.]+'
}

getcidr() {
    ip addr show $1 | grep -Po 'inet [\d.]+\/\K[\d.]+'
}

getnet() {
    IP=$1
    PREFIX=$2
    IFS=. read -r i1 i2 i3 i4 <<< $IP
    D2B=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
    binIP=${D2B[$i1]}${D2B[$i2]}${D2B[$i3]}${D2B[$i4]}
    binIP0=${binIP::$PREFIX}$(printf '0%.0s' $(seq 1 $((32-$PREFIX))))
    # binIP1=${binIP::$PREFIX}$(printf '0%.0s' $(seq 1 $((31-$PREFIX))))1
    echo $((2#${binIP0::8})).$((2#${binIP0:8:8})).$((2#${binIP0:16:8})).$((2#${binIP0:24:8}))/$2
}


getbcast() {
    ip addr show $1 | grep -Po 'brd \K[\d.]+'
}



#---------------------------#
# BPI-R1 VLAN configuration #
#---------------------------#
#
# port ordering (view from front):
# [ 2 1 0 4 ] [ 3 ]
# [ eth0.101 eth0.102 eth0.103 eth0.104 ] [ eth0.201 ]
#

export OUTSIDE_IF=enp1s0
export OUTSIDE_NET=0.0.0.0/0
export OUTSIDE_ADDR=$(getip $OUTSIDE_IF)
export OUTSIDE_BCAST=$(getbcast $OUTSIDE_IF)

echo "###################################################"
echo "[+] Outside Interface: $OUTSIDE_IF"
echo "[+] Address $OUTSIDE_ADDR"
echo "[+] Network $OUTSIDE_NET"
echo "[+] Broadcast $OUTSIDE_BCAST"
echo "[-] "

export INSIDE_IF=enp2s0
export INSIDE_ADDR=$(getip $INSIDE_IF)
export INSIDE_NET=$(getnet $INSIDE_ADDR $(getcidr $INSIDE_IF))
export INSIDE_BCAST=$(getbcast $INSIDE_IF)

echo "[+] Inside Interface: $INSIDE_IF"
echo "[+] Address $INSIDE_ADDR"
echo "[+] Network $INSIDE_NET"
echo "[+] Broadcast $INSIDE_BCAST"
echo "[-] "

export DMZ_IF=enp2s0.100
export DMZ_ADDR=$(getip $DMZ_IF)
export DMZ_NET=$(getnet $DMZ_ADDR $(getcidr $DMZ_IF))
export DMZ_BCAST=$(getbcast $DMZ_IF)

echo "[+] DMZ Interface: $DMZ_IF"
echo "[+] Address $DMZ_ADDR"
echo "[+] Network $DMZ_NET"
echo "[+] Broadcast $DMZ_BCAST"
echo "###################################################"

if [ -z "$OUTSIDE_ADDR" ]
then
	echo "WARNING: cannot determine external IP address"
	exit 1
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
  echo "[+] Disabling IP forwarding"
  echo 0 > /proc/sys/net/ipv4/ip_forward
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
iptables -F -t mangle
iptables -F -t raw

# -Z for Zero the packet and byte counters in all chains
iptables -Z
iptables -Z -t nat
iptables -Z -t mangle
iptables -Z -t raw

# -X for Delete the optional user-defined chain specified. 
# If no argument is given, it will attempt to delete every non-builtin chain in the table. 
iptables -X
iptables -X -t mangle
iptables -X -t nat
iptables -X -t raw

ipset destroy

# add blocking entries at the front of the chains
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
iptables -A FORWARD -j DROP

#Dropping all ipv6 traffic
echo "[+] - I see no need for ipv6 support"
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

# remove after testing
accept_from_outside tcp ssh

#
# Drop broadcast traffic from the inside before logging
#
iptables -A INPUT -p tcp -i $INSIDE_IF -d $INSIDE_BCAST/32 -j DROP -m comment --comment "Drop broadcast traffic"
iptables -A INPUT -p tcp -i $INSIDE_IF -d 255.255.255.255/32 -j DROP -m comment --comment "Drop broadcast traffic"

iptables -A INPUT -p udp -i $INSIDE_IF -d $INSIDE_BCAST/32 -j DROP -m comment --comment "Drop broadcast traffic"
iptables -A INPUT -p udp -i $INSIDE_IF -d 255.255.255.255/32 -j DROP -m comment --comment "Drop broadcast traffic"

iptables -A INPUT -p igmp -i $INSIDE_IF -d 224.0.0.1/32 -j DROP -m comment --comment "Drop broadcast traffic"

iptables -A INPUT -p udp -i $OUTSIDE_IF -d 255.255.255.255/32 -j DROP -m comment --comment "Drop broadcast traffic"
iptables -A INPUT -p udp -i $OUTSIDE_IF -d $OUTSIDE_BCAST/32 -j DROP -m comment --comment "Drop broadcast traffic"


#
# Log anything else
#
iptables -A INPUT -j LOG -m limit --limit 5/min --limit-burst 8  --log-level 3 --log-prefix "fw:ip:INPUT:drop "
iptables -A OUTPUT -j LOG -m limit --limit 5/min --limit-burst 8  --log-level 3 --log-prefix "fw:ip:OUTPUT:drop "
iptables -A FORWARD -j LOG -m limit --limit 5/min --limit-burst 8  --log-level 3 --log-prefix "fw:ip:FORWARD:drop "

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
  echo "[+] - Enabling IP forwarding"
  echo 1 > /proc/sys/net/ipv4/ip_forward
fi

iptables -L -vn

echo "$(date) - ** Firewall configuration complete."

echo "$(date) - ###################################" 	>>/var/log/kern.log
echo "$(date) - ***Firewall reset..."			>>/var/log/kern.log
echo "$(date) - ###################################"	>>/var/log/kern.log

echo "watch -d -n 2 iptables -vL"
echo "iptables -t mangle -L -vn"

exit 0
