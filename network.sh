
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

getip() {
    ip addr show $1 | grep -Po 'inet \K[\d.]+'
}

getcidr() {
    ip addr show $1 | grep -Po 'inet [\d.]+\/\K[\d.]+'
}

getbcast() {
    IP=$1
    PREFIX=$2
IFS=. read -r i1 i2 i3 i4 <<< $IP
D2B=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
binIP=${D2B[$i1]}${D2B[$i2]}${D2B[$i3]}${D2B[$i4]}
binIP0=${binIP::$PREFIX}$(printf '0%.0s' $(seq 1 $((32-$PREFIX))))
# binIP1=${binIP::$PREFIX}$(printf '0%.0s' $(seq 1 $((31-$PREFIX))))1
echo $((2#${binIP0::8})).$((2#${binIP0:8:8})).$((2#${binIP0:16:8})).$((2#${binIP0:24:8}))
}



export INSIDE_IF=enp2s0
export INSIDE_ADDR=$(getip $INSIDE_IF)
export INSIDE_CIDR=$(getcidr $INSIDE_IF)
export INSIDE_NET=$(getnet $INSIDE_ADDR $INSIDE_CIDR)
export INSIDE_BCAST=$(getbcast  $INSIDE_ADDR $INSIDE_CIDR)

#getbcast $INSIDE_ADDR $INSIDE_CIDR

echo "[+] Inside Interface: $INSIDE_IF"
echo "[+] Network $INSIDE_NET"
echo "[+] Address $INSIDE_ADDR"
echo "[+] Broadcast $INSIDE_BCAST"
echo "[-] "
