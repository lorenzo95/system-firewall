#!/bin/sh
#
# Rules controlling traffic to our external port
#

. functions.sh

forward_port_to_lxc ubuntu_lxc 80

exit 0
