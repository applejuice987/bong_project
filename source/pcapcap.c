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

    pcap_lookup(dev, &net, &mask, errbuf);

    addr.s_addr = net;
    printf("IP: %s\n", inet_ntoa(addr));
    addr.s_addr = mask;
    printf("MASK: %s\n", inet_ntoa(addr));

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);

    pcap_setfilter(handle, &fp);

    pcap_loop(handle, 0, got_packet, NULL);

    pcap_close(handle);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char packet)
{

}