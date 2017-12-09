#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
#include "packetinfo.h"

#define ICMP_PROTOCOL_ID 1
#define TCP_PROTOCOL_ID 6
#define UDP_PROTOCOL_ID 17
#define SIZE_ETHERNET 14

int packet_count = 0;

void display_payload_details(u_char* ptr, int len)
{
    int i, count, j;
    char temp[20] = { 0 };

    count = 0;
    while (i < len) {
        temp[count++] = ptr[i];
        printf(" %02x ", ptr[i++]);
        if (i % 15 == 0 || i >= len) {
            printf("\t\t");
            j = 0;
            while (j < 15) {
                if (isprint(temp[j]))
                    printf("%c", temp[j]);
                else
                    printf(".");
                ++j;
            }
            printf("\n");
            count = 0;
        }
    }
    printf("\n");
}

int is_print_allowed(u_char* user, u_char* packet, size_t packet_length)
{
    size_t k = 0;
    while (k < packet_length) {
        if (user[0] == packet[k] && memcmp(user, packet + k, strlen(user)) == 0) {
            return 1;
        }
        ++k;
    }
    return 0;
}

void handle_icmp(const struct pcap_pkthdr* header, u_char* packet, int ip_header_len)
{
    struct icmp* icmp_hdr = (struct icmp*)(packet + SIZE_ETHERNET + ip_header_len);
    printf("\nICMP packet");
    printf("\n***********\n");
    printf("ICMP Type: %d\n", icmp_hdr->icmp_type);
    printf("ICMP Length = %d\n", header->len);
    printf("ICMP Code: %d\n", icmp_hdr->icmp_code);
    printf("\n************\n");
    printf("ICMP PAYLOAD:");
    printf("\n************\n");
    display_payload_details(packet + SIZE_ETHERNET + ip_header_len, header->len - (SIZE_ETHERNET + ip_header_len));
}

void handle_tcp(const struct pcap_pkthdr* header, u_char* packet, int ip_header_len)
{
    tcp_header* tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + ip_header_len);
    printf("\nTCP Packet");
    printf("\n**********\n");
    printf("Source Port: %d\n", ntohs(tcp->sport));
    printf("Destn Port: %d\n", ntohs(tcp->dport));
    printf("TCP Length = %lu\n", (size_t)header->len - (SIZE_ETHERNET + ip_header_len + TH_OFF(tcp)));

    printf("\n*************\n");
    printf("TCP PAYLOAD:");
    printf("\n*************\n");
    display_payload_details(packet + SIZE_ETHERNET + ip_header_len + TH_OFF(tcp), header->len - (SIZE_ETHERNET + ip_header_len + TH_OFF(tcp)));
}

void handle_udp(const struct pcap_pkthdr* header, u_char* packet, int ip_header_len)
{
    udp_header* udp = (struct udp_header*)(packet + SIZE_ETHERNET + ip_header_len);
    printf("\nUDP Packet");
    printf("\n**********\n");
    printf("Source Port: %d\n", ntohs(udp->sport));
    printf("Destn Port: %d\n", ntohs(udp->dport));
    printf("UDP Length = %lu\n", (size_t)header->len - (SIZE_ETHERNET + ip_header_len + 8));
    printf("\n***********\n");
    printf("UDP PAYLOAD:");
    printf("\n***********\n");
    display_payload_details(packet + SIZE_ETHERNET + ip_header_len + 8, header->len - (SIZE_ETHERNET + ip_header_len + 8));
}

void handle_ip_layer(ip_header* ip_layer_header)
{
    printf("\nSource's IP Address:");
    printf("%d.%d.%d.%d ", ip_layer_header->saddr.byte1, ip_layer_header->saddr.byte2, ip_layer_header->saddr.byte3, ip_layer_header->saddr.byte4);
    printf("\nDestination's IP Address:");
    printf("%d.%d.%d.%d ", ip_layer_header->daddr.byte1, ip_layer_header->daddr.byte2, ip_layer_header->daddr.byte3, ip_layer_header->daddr.byte4);
    printf("\n");
}

void hande_ip_and_transport_layer(const struct pcap_pkthdr* header, u_char* packet, int ip_header_len)
{
    /*Internet Protocol layer packet */
    ip_header* ip_layer_header = (ip_header*)(packet + SIZE_ETHERNET);

    /* Print Source and Destination IP Address*/
    handle_ip_layer(ip_layer_header);

    /* TCP or UDP packet */
    ip_header_len = (ip_layer_header->ver_ihl & 0xf) * 4;

    switch (ip_layer_header->proto) {
    case ICMP_PROTOCOL_ID:
        handle_icmp(header, packet, ip_header_len);
        break;
    case TCP_PROTOCOL_ID:
        handle_tcp(header, packet, ip_header_len);
        break;
    case UDP_PROTOCOL_ID:
        handle_udp(header, packet, ip_header_len);
        break;
    default:
        printf("\nOTHER packet\n");
        display_payload_details(packet + SIZE_ETHERNET + ip_header_len, header->len - SIZE_ETHERNET - ip_header_len);
    }

    printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

void print_time_stamp(const struct pcap_pkthdr* header)
{
    int i;
    char time[26];
    printf("timestamp:\t");

    /* Reference: https://www.winpcap.org/docs/docs_412/html/structpcap__pkthdr.html */
    time_t raw_time = (time_t)header->ts.tv_sec;
    strftime(time, 26, "%Y:%m:%d %H:%M:%S", localtime(&raw_time));
    for (i = 0; time[i] != '\0'; i++) {
        printf("%c", time[i]);
    }
}

void print_ether_type(const struct ether_header* arp_hdr)
{
    if (ntohs(arp_hdr->ether_type) == ETHERTYPE_IP) {
        printf("\nEther-type: IP (0x%04x)\n", ETHERTYPE_IP);
    }
    else if (ntohs(arp_hdr->ether_type) == ETHERTYPE_ARP) {
        printf("\nEther-type: ARP (0x%04x)\n", ETHERTYPE_ARP);
    }
    else {
        printf("\nEther-type: Non IP-ARP (0x%04x)\n", ntohs(arp_hdr->ether_type));
    }
}

void print_mac_address(struct ether_header* arp_hdr)
{
    u_char* addr_ptr;

    /*Source MAC Address */
    addr_ptr = arp_hdr->ether_shost;
    int i = ETHER_ADDR_LEN;
    printf("\nSource's MAC Address:");
    while (i > 0) {
        printf("%s%02x", (i == ETHER_ADDR_LEN) ? " " : ":", *addr_ptr++);
        --i;
    };

    /*Destination MAC Address */
    addr_ptr = arp_hdr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf("\nDestination's MAC Address:");
    while (i > 0) {
        printf("%s%02x", (i == ETHER_ADDR_LEN) ? " " : ":", *addr_ptr++);
        --i;
    }
    printf("\n");
}

void parse_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* p)
{
    u_char* packet = (u_char*)p;

    int i = 0, j = 0;
    char* ptr = NULL;
    u_char* pkt = NULL;
    int ip_header_len = 0;

    if (user != NULL && is_print_allowed(user, packet, header->len) == 0)
        return;

    printf("\n%dth packet:\n", ++packet_count);

    /* Print Time Stamp*/
    print_time_stamp(header);

    /* Packet Length */
    printf("\nPacket Length: %d", header->len);

    struct ether_header* arp_hdr = (struct ether_header*)p;

    /* Print Ether Type */
    print_ether_type(arp_hdr);

    /* Print MAC Address*/
    print_mac_address(arp_hdr);

    /* Print IP and Transport Layer Information*/
    if (ntohs(arp_hdr->ether_type) != ETHERTYPE_ARP) {
        hande_ip_and_transport_layer(header, packet, ip_header_len);
    }
}

void capture_offline(char* file_name, char* filter_string, char* payload)
{
    pcap_t* pcap_packet = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int result = 0;
    struct bpf_program fp;

    pcap_packet = pcap_open_offline(file_name, error_buffer);
    if (pcap_packet == NULL) {
        printf("Unable to open pcap file: %s\n", error_buffer);
        return;
    }

    if (filter_string != NULL) {
        result = pcap_compile(pcap_packet, &fp, filter_string, 0, PCAP_NETMASK_UNKNOWN);
        if (result == -1) {
            printf("Failed to compile filter for pcap file : %s\n", pcap_geterr(pcap_packet));
            return;
        }

        result = pcap_setfilter(pcap_packet, &fp);
        if (result == -1) {
            printf("\nSetting device filter failed...\n");
            return;
        }
    }

    result = pcap_loop(pcap_packet, 0, parse_packet, payload);
    if (result < 0) {
        printf("\nAn error occurred in capturing the offline packet...\n");
    }
}

void capture_online(char* interface, char* filter_string, char* payload)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    int result = 0;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t* live_device = NULL;
    struct bpf_program fp;

    live_device = pcap_open_live(interface, BUFSIZ, 1, 0, error_buffer);
    if (live_device == NULL) {
        printf("\nFailed to open the interface: %s\n", error_buffer);
        return;
    }

    if (filter_string) {
        result = pcap_lookupnet(interface, &net, &mask, error_buffer);
        if (result == -1) {
            printf("\nFailed to get netmask of the device ...\nPlease configure the IP of the interface properly before sniffing\n");
            return;
        }

        result = pcap_compile(live_device, &fp, filter_string, 0, net);
        if (result == -1) {
            printf("Failed to compile filter for the device : %s\n", pcap_geterr(live_device));
            return;
        }

        result = pcap_setfilter(live_device, &fp);
        if (result == -1) {
            printf("\nSetting device filter failed...\n");
            return;
        }
    }

    result = pcap_loop(live_device, 0, parse_packet, payload);
    if (result < 0) {
        printf("\nAn error occurred in capturing the live packet...\n");
    }
}

int substring_search(const char* text, const char* pattern)
{
    if (!text || !pattern) {
        return -1;
    }
    int i;
    int j;
    for (i = 0;; ++i) {
        for (j = 0;; ++j) {
            if (pattern[j] == 0) {
                return i;
            }
            if (text[i + j] == 0) {
                return -1;
            }
            if (text[i + j] != pattern[j]) {
                break;
            }
        }
    }
}

int parse_command_line_arguments(char** interface, char** file_name, char** payload, int argc, char** argv)
{
    char cmd_option;
    int argument_count = 0;
    while ((cmd_option = getopt(argc, argv, "i:r:s:")) != -1) {
        if (cmd_option == 'i') {
            *interface = optarg;
            printf("\nStarting to sniff on the interface: %s\n", *interface);
        }
        else if (cmd_option == 'r') {
            *file_name = optarg;
            printf("\nStarting to read from the pcap file: %s\n", *file_name);
        }
        else if (cmd_option == 's') {
            *payload = optarg;
            printf("\nPayload filter applied is: %s\n", *payload);
        }
        else if (cmd_option == '?') {
            printf("\nThe commmand option passed in not supported\n");
        }
        else if (cmd_option == ':') {
            printf("\nMissing of Argument\n");
        }
        ++argument_count;
    }
    return argument_count;
}

int main(int argc, char** argv)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    char* interface = NULL;
    char* file_name = NULL;
    char* payload = NULL;
    char filter_string[50] = { 0 };
    int ind = -1;
    int argument_count = parse_command_line_arguments(&interface, &file_name, &payload, argc, argv);

    /* Set BPF Filter */
    if (argument_count << 1 + 1 < argc) {
        ind = argument_count << 1 + 1;
        while (1) {
            if (argv[ind] == NULL || substring_search((const char*)argv[ind], "-") == -1) {
                break;
            }
            strcat(filter_string, (const char*)argv[ind]);
            strcat(filter_string, " ");
            ++ind;
        }
    }

    if (interface != NULL && file_name != NULL) {
        printf("\nProvide either file name or interface name as input...\n");
        return 0;
    }

    if (interface == NULL && file_name == NULL) {
        interface = pcap_lookupdev(error_buffer);
        if (interface == NULL) {
            printf("\nNot able to find a default sniffing device : %s\n", error_buffer);
            return 0;
        }
    }

    if (file_name != NULL) {
        capture_offline(file_name, filter_string, payload);
    }
    else if (interface != NULL) {
        printf("\nStarting to sniffing on the Default device: %s\n", interface);
        capture_online(interface, filter_string, payload);
    }
    return 0;
}