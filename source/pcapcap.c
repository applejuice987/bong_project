//pcap 캡처 관련된 내용들 들어갈 소스 파일 
//함수별로 매개변수 , 리턴값 등 어떻게 사용해야하는지 주석 달아주세요.

#include "../header/pcapcap.h"

void packet_capture()
{
    char *dev, *errbuf;
    bpf_u_int32 net, mask;
    struct in_addr addr;
    pcap_t *handle;
    struct bpf_program fp;
    char *filter_exp = "src port 80 or src port 443";
    const u_char* packet;

    dev = pcap_lookupdev(errbuf);
    // [용도] network device를 찾는 함수
    // [인자] errbuf - 실패시 에러메세지
    // [성공] network device의 이름
    // [실패] NULL

    pcap_lookupnet(dev, &net, &mask, errbuf);
    // [용도] network address, subnetmask를 찾는 함수
    // [인자] device, ip address 저장주소, subnetmask 저장주소, 실패시 에러메세지
    // [성공] 0
    // [실패] PCAP_ERROR = -1

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // [용도] packet capture를 위한 handle을 얻는 함수
    // [인자] device, 버퍼사이즈, promiscuous mode, read timeout, 실패시 에러메세지
    // [성공] pcap_t* packet capture handle
    // [실패] NULL

    pcap_compile(handle, &fp, filter_exp, 0, net);
    // [용도] filter를 bpf_program에 저장하는 함수
    // [인자] handle, bpf_program, filter, 최적화, netmask
    // [성공] 0
    // [실패] PCAP_ERROR

    pcap_setfilter(handle, &fp);
    // [용도] pcap_compile()에서 저장된 filter를 적용하는 함수
    // [인자] handle, bpf_program
    // [성공] 0
    // [실패] PCAP_ERROR

    pcap_loop(handle, 0, got_packet, NULL);
    // [용도] 실제 packet capture하는 함수
    // [인자] handle, 읽는 cnt (0 = 무한), callback 함수, callback 함수 첫번째 인자
    // [성공] cnt가 0이 되면 0 반환
    // [실패] PCAP_ERROR
    // [비고] pcap_dispatch, pcap_next, pcap_next_ex로 대체 가능

    pcap_close(handle);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char packet)
{
    const MAC *mac;
    const IP *ip;
    const TCP *tcp;
    u_int size_ip, size_tcp;

    // MAC 주소
    mac = (MAC*)(packet);
    printf("src MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%02x ", mac->ether_shost[i]);
    puts("");

    printf("src MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%02x ", mac->ether_dhost[i]);
    puts("");

    // IP 주소
    ip = (IP*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    printf("src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));

    // TCP 주소
    tcp = (TCP*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    printf("src PORT: %d\n", ntohs(tcp->th_sport));
    printf("dst PORT: %d\n", ntohs(tcp->th_dport));
}