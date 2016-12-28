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
	net=$2

	iptables -A FORWARD -p $proto \
        -i $INSIDE_IF -s $net \
		$TO_OUTSIDE \
		-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

	iptables -A FORWARD -p $proto \
        -o $INSIDE_IF -d $net \
		$FROM_OUTSIDE \
		-m conntrack --ctstate=ESTABLISHED -j ACCEPT

#	iptables -t nat -A POSTROUTING \
#		-s $net -p $proto \
#		$TO_OUTSIDE -j MASQUERADE
}

allow_to_nameserver()
{
	echo "$(date) - Allow all traffic to and from DNS servers"
	for dnsserverip in `grep nameserver /etc/resolv.conf | sed 's/.* //'` ; do
        	iptables -A OUTPUT -o $OUTSIDE_IF -d $dnsserverip -p udp --dport domain \
			--sport 1024:65535 -s $OUTSIDE_ADDR \
			-m conntrack --ctstate=NEW,ESTABLISHED -j ACCEPT

        	iptables -A INPUT -i $OUTSIDE_IF -s $dnsserverip -p udp --sport domain \
			--dport 1024:65535 -d $OUTSIDE_ADDR \
			-m conntrack --ctstate=ESTABLISHED -j ACCEPT
	done
}
