//pcapcap.c 에 있는 함수 원형 등 적으면됨.

#include <pcap.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define SIZE_MIN_IP 20
#define SIZE_MIN_TCP 20

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
#define sendraw_mode 1
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

// 이더넷 헤더 구조체
typedef struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
}   MAC;

// IP 헤더 구조체
typedef struct sniff_ip
{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_DF 0x4000
    #define IP_RF 0x8000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
}   IP;

// TCP 헤더 구조체
typedef u_int tcp_seq;
typedef struct sniff_tcp
{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
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
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
}   TCP;

void packet_capture_setter(pcap_t**,int);
int got_packet(const u_char*, u_char** got_info, int);