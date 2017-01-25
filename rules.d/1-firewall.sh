#!/bin/sh
#
# Rules controlling traffic to/from the firewall itself 
#

. functions.sh

# logging
#allow_to_inside tcp 514

#web for testing
#allow_to_outside tcp http
#allow_to_outside tcp https

# DNS
#allow_to_outside tcp domain
#allow_to_outside udp domain
allow_to_nameserver

# NTP
allow_to_outside udp ntp

# DHCP
allow_to_outside udp 67:68
accept_from_outside udp 68

# DNS
accept_from_inside udp domain
#accept_from_inside tcp domain
accept_from_dmz udp domain
#accept_from_dmz tcp domain

# DNS (temporary)
#allow_to_inside udp domain

exit 0

