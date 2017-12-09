*************************
Sandeep Kumta Vishnu
SBU ID: 111482809
*************************

Implementation
**************************************************************************************
The programs use python's scapy library to play with the packets

Part1:
* Based on the specified interface(or all the interfaces), Sniffing is done on those using scapy's sniff function. 
* A filter is added to recieve only the packets with dns query. i.e udp port 53.
* Once it is sniffed, a specified callback function is called where we do all the magic of poisoning the packet.
* If [-h hostnames] is specified, hostnames file is read and created a dictionary with the domain names as key and poisonous ip as the value. If the hostnames file is specified, the victim's query is checked in the dictionary and if present the corresponding poisonous ip is used while creating the spoofed packet. If the hostname file is not specified then attacker's ip is used as poisonous ip to create spoofed packet.
* A proper spoofed ip is created by Scapy's API

Part2:
* There are again two varieties how this program can be used (a) online (b) offline
* If it is in online mode then all the packets in victim in all the interfaces. 
* If it is an offline mode then pcap file is scanned to read the packets.
* Once a packet is sniffed, it is sent to the callback function where it is added to a dictionary with packet's [DNS].id {transaction id} as the key. When new packet comes if the new id is already present in the dictionary then appropriate checks are done to see if the packet is poisoned. i.e when a packet is received with same destination IP, source port, Destination port, Request URL, but different response IP and the payload as compared to a packet already in the dictionary.
* Once poisoning is detected meaningful message is printed.

Assumptions:
***************
The DNS address of the victim is changed to Google's DNS 8.8.8.8 from the Stony Brook's default DNS Server. The program is succesful in winning against google but not Stony Brook's DNS server :P

What is needed for the Program to compile?
*******************************************
1. Needs Python 2.7.X
2. Install scrapy module using the command 'pip install Scrapy'


How to Run!
**************************************************************

1. dnsinject

To inject on all the interfaces
$ sudo python dnsinject.py

To inject only on enp0s3 interface
$ sudo python dnsinject.py -i enp0s3

To inject on enp0s3 interface and to use hostnames file
$ sudo python dnsinject.py -i enp0s3 -f hostname

To inject on specific victim's IP
$ sudo python dnsinject.py -i enp0s3 -f hostname 172.24.30.234


2. dnsdetect

For all the interfaces and packets with dns query
$ sudo python dnsdetect.py 'udp port 53'

For enp0s3 interface and packets with dns query
$ sudo python dnsdetect.py -i enp0s3 'udp port 53'

For offline pcap file and dns traffic
$ sudo python dnsdetect.py -r enp0s3.pcap 'udp port 53'


Demo:
[I] DNS Inject
1. Get ip address of victim by running $ ifconfig. 
Got: 172.24.17.105

2. Attacker Machine 
$ sudo python dnsinject.py -h hostnames 172.24.30.234

Poisoning Query Table read from:  hostnames
Intended Victim: ['172.24.30.234']
Capture on all interfaces

3. Victim Machine
$ nslookup www.cs.stonybrook.edu                                                 
Server:         8.8.8.8  
Address:        8.8.8.8#53                         

Name:   www.cs.stonybrook.edu                      
Address: 192.168.66.6

4. In attacker Machine:
Sent 1 packets.
Posioned Response: 192.168.66.6
Sent packet IP / UDP / DNS Ans "192.168.66.6"


[II] DNS Detect
1. Capture packet in a pcap file when the attack has intended to happen.
2. In the victim machine run this,

$ sudo python dnsdetect.py -r enp0s3.pcap 'udp port 53'
Checking for DNS Poisoning from the tracefile: enp0s3.pcap
DNS Poisoning attempt detected
TXID 55749 Request foo.example.com
Answer1  172.31.81.46
Answer2  snsdnsicannorgnoc1x: u 

DNS Poisoning attempt detected
TXID 17026 Request google.com
Answer1  172.31.81.46
Answer2  172.217.11.46 

DNS Poisoning attempt detected
TXID 64716 Request www.cs.stonybrook.edu
Answer1  172.31.81.46
Answer2  129.49.2.176 

DNS Poisoning attempt detected
TXID 10308 Request facebook.com
Answer1  172.31.81.46
Answer2  31.13.69.228 


Reference:
---------------
1. https://scapy.readthedocs.io/en/latest/
2. http://archive.is/PVPmh