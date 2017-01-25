lxc-stop -n ubuntu_lxc
lxc-start -n ubuntu_lxc -d
sleep 3
lxc-ls -f

