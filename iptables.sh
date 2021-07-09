#!/bin/bash

# Disclaimer: Basic iptables firewall for a VPN service using OpenVPN on UDP.
# Feel free to add your own iptables as you'd like. 
# Just make sure they are under # OpenVPN and before the -P INPUT DROP rule.

iptables="/sbin/iptables"
homeconnection=
vpnIP=
sshport=
serverIP=
interface=
openvpnport=
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
	# Connections
	$iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
	$iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
	$iptables -A INPUT -s $homeconnection -p tcp -m tcp --dport $sshport -j ACCEPT
	$iptables -A INPUT -s $vpnIP -p tcp -m tcp --dport $sshport -j ACCEPT
 	$iptables -A INPUT -d $serverIP/32 -p icmp --icmp-type 8 -j ACCEPT
	$iptables -A INPUT -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
 	$iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	# OpenVPN Filter (Basic)
  	$iptables -A INPUT -p udp -m udp -m length --length 82:84 --dport $openvpnport -j ACCEPT
	$iptables -t raw -A PREROUTING -p udp -m udp -m length --length 1:81 --dport $openvpnport -j DROP
	$iptables -t raw -A PREROUTING -p udp -m udp -m length --length 85:89 --dport $openvpnport -j DROP
	$iptables -t raw -A PREROUTING -p udp -m udp --sport 1194 --dport $openvpnport -j DROP # Blocks CVE Exploit
	# OpenVPN
	$iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $interface -j MASQUERADE
	$iptables -A INPUT -i tun0 -j ACCEPT
	$iptables -A FORWARD -i $interface -o tun0 -j ACCEPT
	$iptables -A FORWARD -i tun0 -o $interface -j ACCEPT
	# TCP Protection
	$iptables -N TCP-PROTECTION -t mangle
	$iptables -t mangle -A PREROUTING -p tcp -m tcp -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j TCP-PROTECTION
	$iptables -t mangle -A PREROUTING -p tcp --syn -m conntrack --ctstate NEW -m hashlimit --hashlimit-above $hashlimitsyn --hashlimit-mode srcip --hashlimit-name SYN-LIMIT -j TCP-PROTECTION
	$iptables -t mangle -A PREROUTING -m hashlimit -p tcp -m multiport --dports 80,443 --hashlimit-above $hashlimittcp --hashlimit-mode srcip --hashlimit-name TCP-ATTACK -j TCP-PROTECTION
	$iptables -t mangle -A TCP-PROTECTION -j DROP
	# UDP Protection
	$iptables -N DNS-PROTECTION -t raw
	$iptables -t raw -A PREROUTING -p udp --sport 53 -m string --from 40 --algo bm --hex-string '|00 00 ff 00 01|' -j DNS-PROTECTION
	$iptables -t raw -A PREROUTING -p udp --sport 53 -m length --length 1:50 -j DNS-PROTECTION
	$iptables -t raw -A DNS-PROTECTION -j DROP
	$iptables -t raw -A PREROUTING -p udp -m udp ! --dport $openvpnport -m hashlimit --hashlimit-above $hashlimitudp --hashlimit-mode srcip --hashlimit-name UDP-LIMIT -j DROP	
	# Block Traffic
	$iptables -P INPUT DROP # Any traffic not matching any of the accepted applied rulesets above is blocked.
echo "VPN firewall added."
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
