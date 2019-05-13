
fping -a -I eth0 -R -g 10.156.158.0/24
netdiscover -i eth0 -P -r 10.156.158.0/24
arp-scan --interface=eth0 10.156.158.0/24