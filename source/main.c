//main함수 진행될 파일

#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"

int main()
{
    const IP *got_ip;
    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_t *handle;

    packet_capture_setter(&handle);

    // 테스트
    // pcap_next_ex(handle, &header, &packet);
    // got_packet(packet, &got_ip);

    while(pcap_next_ex(handle, &header, &packet) == 1)
        got_packet(packet, &got_ip);

    // [용도] packet에 정보를 전달하는 함수
    // [인자] handle, packet의 header 구조체, packet 정보
    // [성공] 1
    // [실패] 시간초과 0, 실패 PCAP_ERROR

    printf("got_ip: %s \n", inet_ntoa(got_ip->ip_dst));

    pcap_close(handle);
}