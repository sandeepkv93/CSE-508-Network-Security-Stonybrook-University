/* 
 *  The following structure definations are taken from https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html
 */

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

/* IPv4 header */
typedef struct ip_header {
    u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
    u_char tos; // Type of service
    u_short tlen; // Total length
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl; // Time to live
    u_char proto; // Protocol
    u_short crc; // Header checksum
    ip_address saddr; // Source address
    ip_address daddr; // Destination address
    u_int op_pad; // Option + Padding
} ip_header;

/* UDP header*/
typedef struct udp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len; // Datagram length
    u_short crc; // Checksum
} udp_header;

/* 
 *  The following structure definations are taken from http://www.tcpdump.org/pcap.html
 */

typedef struct tcp_header {
    u_short sport; /* source port */
    u_short dport; /* destination port */
    u_int th_seq; /* sequence number */
    u_int th_ack; /* acknowledgement number */
    u_char th_offx2; /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
} tcp_header;

/* 
 *  The following structure definations are taken from http://www.programming-pcap.aldabaknocking.com/code/arpsniffer.c
 */

typedef struct arp_header_ {
    u_int16_t htype; /* Hardware Type           */
    u_int16_t ptype; /* Protocol Type           */
    u_char hlen; /* Hardware Address Length */
    u_char plen; /* Protocol Address Length */
    u_int16_t oper; /* Operation Code          */
    u_char sha[6]; /* Sender hardware address */
    u_char spa[4]; /* Sender IP address       */
    u_char tha[6]; /* Target hardware address */
    u_char tpa[4]; /* Target IP address       */
} arp_header;