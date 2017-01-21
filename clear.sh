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

ipset destroy

# -X for Delete the optional user-defined chain specified. 
# If no argument is given, it will attempt to delete every non-builtin chain in the table. 
iptables -X

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT