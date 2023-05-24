//pcapmodu.c 에 있는 함수 원형 등 적으면됨.

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <ctype.h>

struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

u_short in_cksum ( u_short *addr , int len );

void sendraw (const u_char* pre_packet , int mode );