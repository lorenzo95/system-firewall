#!/bin/sh
#
# Rules controlling traffic to our external port
#

if [ -z "$LXC_ADDR" ]
then
	echo "WARNING: cannot determine LXC interface IP address"
	exit 1
fi


. functions.sh

#contint=ip addr show | grep -Po 'veth.+?(?=@)'

# Allow broadcast traffic for DHCP to flow
iptables -A INPUT -i lxcbr0 -j ACCEPT -m comment --comment "Allow LXC Containers in w DHCP"
iptables -A OUTPUT -o lxcbr0 -j ACCEPT -m comment --comment "Allow LXC Containers out w DHCP"

# Bypass PSD for DHCP server traffic
iptables -t raw -I PREROUTING 2 -i lxcbr0 -m pkttype --pkt-type broadcast -j ACCEPT -m comment --comment "Bypass LXC Container DHCP traffic"


# Port Forward
forward_port_to_lxc ubuntu_lxc 80

exit 0
