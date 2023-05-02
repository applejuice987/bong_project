//pcap 캡처 관련된 내용들 들어갈 소스 파일 
//함수별로 매개변수 , 리턴값 등 어떻게 사용해야하는지 주석 달아주세요.

#include "../header/pcapcap.h"

void packet_capture_setter(pcap_t **handle)
{
    pcap_if_t *dev;
    char *errbuf;
    bpf_u_int32 net, mask;
    struct bpf_program fp;
    char *filter_exp = "dst port 80 or dst port 443";
    const u_char* packet;

    pcap_findalldevs(&dev, errbuf);
    // [용도] network device의 리스트를 구하는 함수
    // [인자] device 리스트를 저장할 포인터, errbuf 에러메세지
    // [성공] 0
    // [실패] PCAP_ERROR = -1

    // dev = pcap_lookupdev(errbuf);
    // [용도] network device를 찾는 함수
    // [인자] errbuf - 실패시 에러메세지
    // [성공] network device의 이름
    // [실패] NULL

    pcap_lookupnet(dev[0].name, &net, &mask, errbuf);
    // [용도] network address, subnetmask를 찾는 함수
    // [인자] device, ip address 저장주소, subnetmask 저장주소, 실패시 에러메세지
    // [성공] 0
    // [실패] PCAP_ERROR = -1

    *handle = pcap_open_live(dev[0].name, BUFSIZ, 1, 1000, errbuf);
    // [용도] packet capture를 위한 handle을 얻는 함수
    // [인자] device, 버퍼사이즈, promiscuous mode, read timeout, 실패시 에러메세지
    // [성공] pcap_t* packet capture handle
    // [실패] NULL

    pcap_compile(*handle, &fp, filter_exp, 0, net);
    // [용도] filter를 bpf_program에 저장하는 함수
    // [인자] handle, bpf_program, filter, 최적화, netmask
    // [성공] 0
    // [실패] PCAP_ERROR

    pcap_setfilter(*handle, &fp);
    // [용도] pcap_compile()에서 저장된 filter를 적용하는 함수
    // [인자] handle, bpf_program
    // [성공] 0
    // [실패] PCAP_ERROR
}

void got_packet(const u_char* packet, u_char** got_ip)
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

    printf("dst MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%02x ", mac->ether_dhost[i]);
    puts("");

    // IP 주소
    ip = (IP*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    printf("src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
    *got_ip = inet_ntoa(ip->ip_dst);

    // TCP 주소
    tcp = (TCP*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    printf("src PORT: %d\n", ntohs(tcp->th_sport));
    printf("dst PORT: %d\n", ntohs(tcp->th_dport));
}