#!/bin/bash

# set -x

action=$1
ifname=$2
bpffilename="/ratelimit/bin/ratelimit_kern.o"

echo "Action: $action, Interface: $ifname"
case $1 in
    "addtun")
        num_qdisc=$(tc qdisc show dev $ifname | grep -c "clsact")
        if [ $num_qdisc == 0 ]; then
            tc qdisc add dev $ifname clsact
        fi

        num_egress=$(tc filter show dev $ifname egress | grep -c "ratelimit")
        if [ $num_egress == 0 ]; then
            tc filter add dev $ifname egress bpf da obj $bpffilename sec ratelimit/tun/egress
        fi

        num_ingress=$(tc filter show dev $ifname ingress | grep -c "ratelimit")
        if [ $num_ingress == 0 ]; then
            tc filter add dev $ifname ingress bpf da obj $bpffilename sec ratelimit/tun/ingress
        fi
        ;;
    "addtap")
        num_qdisc=$(tc qdisc show dev $ifname | grep -c "clsact")
        if [ $num_qdisc == 0 ]; then
            tc qdisc add dev $ifname clsact
        fi

        num_egress=$(tc filter show dev $ifname egress | grep -c "ratelimit")
        if [ $num_egress == 0 ]; then
            tc filter add dev $ifname egress bpf da obj $bpffilename sec ratelimit/tap/egress
        fi

        num_ingress=$(tc filter show dev $ifname ingress | grep -c "ratelimit")
        if [ $num_ingress == 0 ]; then
            tc filter add dev $ifname ingress bpf da obj $bpffilename sec ratelimit/tap/ingress
        fi
        ;;
    "del")
        tc qdisc del dev $ifname clsact
        ;;
    "show")
        tc qdisc show dev $ifname
        tc filter show dev $ifname egress
        tc filter show dev $ifname ingress
        ;;
    *)
        echo "Usage: $0 {addtun|addtap|del|show} <interface>"
        exit 1
        ;;
esac