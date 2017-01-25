#!/bin/sh

forward_to_outside()
{
	proto=$1
	port=$2

        if [ "$3" ]
        then
            src_restrict="-i $OUTSIDE_IF -s $3"
            dst_restrict="-o $OUTSIDE_IF -d $3"
        else
            src_restrict=$FROM_OUTSIDE
            dst_restrict=$TO_OUTSIDE
        fi

	iptables -A FORWARD -p $proto --dport $port \
		$FROM_INSIDE $dst_restrict \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A FORWARD -p $proto --sport $port \
		$src_restrict $TO_INSIDE \
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT
}

forward_to_inside()
{
	proto=$1
	port=$2

	iptables -A FORWARD -p $proto --dport $port \
		$FROM_OUTIDE $TO_INSIDE \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A FORWARD -p $proto --sport $port \
		$FROM_INSIDE $TO_OUTSIDE \
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT
}

accept_from_outside()
{
	proto=$1
	port=$2

	iptables -A INPUT -p $proto --dport $port \
		$FROM_OUTSIDE -d $OUTSIDE_ADDR\
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A OUTPUT -p $proto --sport $port \
		$TO_OUTSIDE -s $OUTSIDE_ADDR\
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT
}

accept_from_inside()
{
	proto=$1
	port=$2

	iptables -A INPUT -p $proto --dport $port \
		$FROM_INSIDE -d $INSIDE_ADDR \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A OUTPUT -p $proto --sport $port \
		$TO_INSIDE -s $INSIDE_ADDR \
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT
}

accept_from_dmz()
{
	proto=$1
	port=$2

	iptables -A INPUT -p $proto --dport $port \
		$FROM_DMZ -d $DMZ_ADDR \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A OUTPUT -p $proto --sport $port \
		$TO_DMZ -s $DMZ_ADDR \
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT
}



allow_to_outside()
{
	proto=$1
	port=$2

	iptables -A OUTPUT -p $proto --dport $port \
		$TO_OUTSIDE -s $OUTSIDE_ADDR \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A INPUT -p $proto --sport $port \
		$FROM_OUTSIDE -d $OUTSIDE_ADDR \
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT
}

allow_to_inside()
{
	proto=$1
	port=$2

	iptables -A OUTPUT -p $proto --dport $port \
		$TO_INSIDE  -s $INSIDE_ADDR \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A INPUT -p $proto --sport $port \
		$FROM_INSIDE -d $INSIDE_ADDR\
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT
}

forward_host_to_outside()
{
	
	proto=$1
	INT=$2
	NET=$3

	iptables -A FORWARD -p $proto \
        -i $INT -s $NET \
		$TO_OUTSIDE \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A FORWARD -p $proto \
        -o $INT -d $NET \
		$FROM_OUTSIDE \
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT

#	iptables -t nat -A POSTROUTING \
#		-s $net -p $proto \
#		$TO_OUTSIDE -j MASQUERADE
}

allow_to_nameserver()
{
	for dnsserverip in `grep nameserver /etc/resolv.conf | sed 's/.* //'` ; do
        	iptables -A OUTPUT -o $OUTSIDE_IF -d $dnsserverip -p udp --dport domain \
			--sport 1024:65535 -s $OUTSIDE_ADDR \
			-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

        	iptables -A INPUT -i $OUTSIDE_IF -s $dnsserverip -p udp --sport domain \
			--dport 1024:65535 -d $OUTSIDE_ADDR \
			-m conntrack --ctstate=ESTABLISHED -j ACCEPT
	done
}




forward_port_to_lxc()
{
	# First, we want to transfer packets from outside to the LXC port 
	# on our external address to the LXC port on our server.
	#
	# Secondly, for devices that can be connected to external or internal 
	# networks, we redirect connections to the external address directly
	# to the LXC server.
	#

	LXC_SERVER_IP=$(lxc-info -n $1 | awk '/^IP:/ {print $2}')
	LXC_SERVER_PORT=$2

	#
	# Rewrite/redirect connections to our public port via DNAT (rewrite
	# destination address) and SNAT (rewrite source address).
	#
	iptables -t nat -A PREROUTING -p tcp \
		-i $OUTSIDE_IF --dport $LXC_SERVER_PORT  \
		-j DNAT --to-destination $LXC_SERVER_IP:$LXC_SERVER_PORT

	iptables -t nat -A POSTROUTING -p tcp \
		-o $LXC_IF -d $LXC_SERVER_IP --dport $LXC_SERVER_PORT  \
		-j SNAT --to $LXC_ADDR

	#
	# Forward the incoming connections through the firewall
	#
	iptables -A FORWARD -p tcp \
		-i $OUTSIDE_IF \
		-o $LXC_IF -d $LXC_SERVER_IP --dport $LXC_SERVER_PORT \
		-m conntrack --ctstate NEW \
		-m limit --limit 60/s --limit-burst 20 \
		-j ACCEPT

	iptables -A FORWARD -p tcp \
		-i $OUTSIDE_IF \
		-o $LXC_IF -d $LXC_SERVER_IP --dport $LXC_SERVER_PORT \
		-m conntrack --ctstate NEW -j DROP

	iptables -A FORWARD -p tcp \
		-i $OUTSIDE_IF \
		-o $LXC_IF -d $LXC_SERVER_IP --dport $LXC_SERVER_PORT \
		-m conntrack --ctstate ESTABLISHED \
		-j ACCEPT

	iptables -A FORWARD -p tcp \
		-i $LXC_IF -s $LXC_SERVER_IP --sport $LXC_SERVER_PORT \
		-o $OUTSIDE_IF \
		-m state --state ESTABLISHED -j ACCEPT

	#
	# Redirect outgoing connections to the public port back to the
	# internal server.
	#
	# I use this so that if I can switch portable device between the inside and
	# outside networks and just have them configured with the external address
	# of the mail server.  Otherwise you probably don't need to use these
	# rules.
	#
	if [ "$OUTSIDE_ADDR" ]
	then
		iptables -t nat -A PREROUTING -p tcp \
			-i $INSIDE_IF -s $INSIDE_NET -d $OUTSIDE_ADDR --dport $LXC_SERVER_PORT \
			-j DNAT --to-destination $LXC_SERVER_IP:$LXC_SERVER_PORT

        	iptables -A FORWARD -p tcp \
                	-i $INSIDE_IF \
	                -o $LXC_IF -d $LXC_SERVER_IP --dport $LXC_SERVER_PORT \
	                -m state --state NEW,ESTABLISHED -j ACCEPT

        	iptables -A FORWARD -p tcp \
                	-i $LXC_IF -s $LXC_SERVER_IP --sport $LXC_SERVER_PORT \
	                -o $INSIDE_IF \
	                -m state --state ESTABLISHED -j ACCEPT
	else
		echo "NOTE: not redirecting outgoing imaps connections to mail server"
	fi
}
