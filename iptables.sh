#!/bin/bash

# Disclaimer

# Basic iptables firewall for a VPN service using OpenVPN on UDP.
# Helps mitigate DDoS attacks that leak from the edge. For better
# performance, use a higher port speed than 1G 
# so you aren't prone to port saturation.

# For "OpenVPN Filter" to work, you must insert a BPF filter that 
# matches your OpenVPN setup. Thus, requires you to analyze traffic.

# This iptables firewall can indeed be optimized 
# by altering the structure a bit and adding other
# filering techniques, however as stated earlier,
# it's something basic that can efficiently 
# mitigate DDoS attacks.

# Feel free to add your own iptables as you'd like. Just make sure 
# they are before the -P INPUT DROP rule.

# Need help making an OpenVPN (UDP) filter? 
# Contact: Skedaddle#0091 on Discord.

# Or, you can use this guide below made by Courvix.
# https://github.com/Courvix/OpenVPN-DDoS-Protection
# Along with his ipt generator for making a filter.
# https://courvix.com/bpf.php

# End

iptables="/sbin/iptables"
homeconnection=
vpnIP=
sshport=
serverIP=
interface=
vpnport=
hashlimitsyn=
hashlimittcp=
hashlimitudp=

# Hashlimit = time/sec/min/hr/day
# Example = 1000/sec

echo
echo " Created by Skedaddle"
echo
echo " VPN Firewall"
echo 
echo " 1. Load Firewall"
echo " 2. Clear Firewall"
echo
echo " Please choose a module: "
read tmp
echo

if test "$tmp" = "1"
then
 	# Block Invalid Packets
	$iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
	$iptables -t raw -A PREROUTING -f -j DROP
	# Connections
	$iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
	$iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
	$iptables -A INPUT -s $homeconnection -p tcp -m tcp --dport $sshport -j ACCEPT
	$iptables -A INPUT -s $vpnIP -p tcp -m tcp --dport $sshport -j ACCEPT
 	$iptables -A INPUT -d $serverIP/32 -p icmp --icmp-type 8 -j ACCEPT
	$iptables -A INPUT -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
 	$iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	# OpenVPN Filter
  	$iptables -A INPUT -p udp -m conntrack --ctstate NEW  -m bpf --bytecode "" -j ACCEPT
	$iptables -t raw -A PREROUTING -p udp -m udp --sport 1194 --dport $vpnport -j DROP # Blocks CVE Exploit
	# OpenVPN
	$iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $interface -j MASQUERADE
	$iptables -A INPUT -i tun0 -j ACCEPT
	$iptables -A FORWARD -i $interface -o tun0 -j ACCEPT
	$iptables -A FORWARD -i tun0 -o $interface -j ACCEPT
	# TCP Protection
	$iptables -N TCP-PROTECTION -t mangle
	$iptables -t mangle -A PREROUTING -p tcp --syn -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-mode srcip --hashlimit-name SYN-LIMIT -j TCP-PROTECTION
	$iptables -t mangle -A PREROUTING -p tcp -m multiport --dports 80,443 -m hashlimit --hashlimit-above 50/sec --hashlimit-mode srcip --hashlimit-name TCP-ATTACK -j TCP-PROTECTION
	$iptables -t mangle -A PREROUTING -p tcp -m tcp -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j TCP-PROTECTION
	$iptables -t mangle -A TCP-PROTECTION -j DROP
	# UDP Protection
	$iptables -N UDP-PROTECTION -t raw
	$iptables -t raw -A PREROUTING -p udp --sport 53 -m string --from 40 --algo bm --hex-string '|00 00 ff 00 01|' -j UDP-PROTECTION
	$iptables -t raw -A PREROUTING -p udp --sport 53 -m length --length 1:50 -j UDP-PROTECTION
	$iptables -t raw -A PREROUTING -p udp -m udp ! --dport $vpnport -m hashlimit --hashlimit-above 100/sec --hashlimit-mode srcip --hashlimit-name UDP-LIMIT -j UDP-PROTECTION	
	$iptables -t raw -A UDP-PROTECTION -j DROP
	# Drop All Policy
	$iptables -P INPUT DROP
echo "Firewall added."
elif test "$tmp" = "2"
then
	# Clear Firewall
	$iptables -t nat -F
	$iptables -t mangle -F
 	$iptables -t raw -F
	$iptables -F
	$iptables -X
	$iptables -t nat -X
	$iptables -t mangle -X
	$iptables -t raw -X
	$iptables -P INPUT ACCEPT
	$iptables -P FORWARD ACCEPT
	$iptables -P OUTPUT ACCEPT
echo "Firewall cleared."
fi
