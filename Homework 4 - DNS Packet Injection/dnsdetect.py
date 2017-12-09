#!/usr/bin/env python
import argparse
from scapy.all import *

packet_dict = {}


'''
    Prints information about DNS Poison detection
'''
def print_poisoning_info(packet,old_packet):
    print 'DNS Poisoning attempt detected'
    print 'TXID', old_packet[DNS].id,'Request',old_packet[DNS].qd.qname.rstrip('.')
    print 'Answer1 ', old_packet[DNSRR].rdata
    print 'Answer2 ', packet[DNSRR].rdata, '\n'

'''
    Recieves a packet specified interfaces and checks in packet_dict for the verification.   
'''
def detect_dns_poison(packet):
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):
        if packet[DNS].id in packet_dict:
            old_packet = packet_dict[packet[DNS].id]
            if old_packet[IP].dst == packet[IP].dst and old_packet[IP].sport == packet[IP].sport and old_packet[IP].dport == packet[IP].dport and old_packet[DNS].qd.qname == packet[DNS].qd.qname and old_packet[DNSRR].rdata != packet[DNSRR].rdata and old_packet[IP].payload != packet[IP].payload:
                print_poisoning_info(packet,old_packet)
        packet_dict[packet[DNS].id] = packet

'''
    Parses the command line arguments
'''
def parse_cmd_line_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i')
    parser.add_argument('-r')
    parser.add_argument('expression', nargs='*', action="store")
    args = parser.parse_args()
    return args.i, args.r, args.expression


'''
    Main function
'''
if __name__ == '__main__':
    interface, tracefile, expression = parse_cmd_line_args()
    if interface and tracefile:
        print 'Enter only one argument - Eiter the pcap or the interface is supported, not both'
    elif interface:
        print 'Checking for DNS Poisoning on interface:',interface
        sniff(filter=expression, iface=interface, store=0, prn=detect_dns_poison)
    elif tracefile:
        print 'Checking for DNS Poisoning from the tracefile:',tracefile
        sniff(filter=expression, offline = tracefile, store=0, prn=detect_dns_poison)
    else:
        print "Checking for DNS Poisoning on all interfaces"
        sniff(filter=expression, store=0, prn=detect_dns_poison)