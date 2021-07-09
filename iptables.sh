#!/bin/bash

# Disclaimer: Basic firewall that should do you justice if your hosting provider isn't retarded.
# This is primarily for running OpenVPN on UDP, if you'd like to implement a sucessful OpenVPN TCP -> you'd need to implement stateful filtering, iptables won't do much
# For attacks that target your OpenVPN filter, you can play around with length filtering, however, I'd suggest not using a GAME OVH
# as any port that's on the GAME firewall (not beta) will leak
# note that you'll still be affected by DrDoS SYN, the limit can only do soo much, I'd suggest routing your TCP traffic to a Frantech server or any server that has
# stateful filtering implemented -> however, if you use OVH GAME (beta firewall), you should be fine.
# You may have also noticed that I'm not blocking amps src ports. On this type of firewall, that is not needed as all traffic not matching
# any of the rules sets is automatically blocked.
# if you would like to implement amp src ports, you can do so at your free will, i've made a section for it
# if there are any typos that may hinder this script from working, run a dry-run
# if you want to add any of your firewalls that you think may be useful, feel free to do so. Just make sure they
# are added before the -P INPUT DROP rule and after the # OpenVPN section

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

# example for hashlimitsyn/tcp/udp: 100/sec or 300/sec -> use it in those direct values... time/sec or minute or whichever one you want

echo
echo
echo " IP Tables Firewall"
echo 
echo " 1. VPN"
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
	$iptables -t raw -A PREROUTING -p udp -m udp --sport 1194 --dport $openvpnport -j DROP # Blocks that shit OpenVPN method
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
	# AMP Protection
	$iptables -t AMP-PROTECTION -t raw
	# import iptables rule here using the raw table... for TCP -> do not use -t raw, you need to implement stateful filtering
	$iptables -t raw -A AMP-PROTECTION -j DROP 	
	# Block the rest of traffic
	$iptables -P INPUT DROP # may make NAT moderate, an alternative to this would be blocking protocols not needed and adding more filtering to UDP/TCP
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
