//main함수 진행될 파일

#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"

int main()
{
    pcap_t *handle;
    packet_capture_setter(&handle);
    pcap_loop(handle, 1, got_packet, NULL);
    // [용도] 실제 packet capture하는 함수
    // [인자] handle, 읽는 cnt (0 = 무한), callback 함수, callback 함수 첫번째 인자
    // [성공] cnt가 0이 되면 0 반환
    // [실패] PCAP_ERROR
    // [비고] pcap_dispatch, pcap_next, pcap_next_ex로 대체 가능

    printf("captured ip: %s \n", inet_ntoa(ip->ip_dst));
    pcap_close(handle);
}