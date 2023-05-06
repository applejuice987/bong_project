//pcap 캡처 관련된 내용들 들어갈 소스 파일 
//함수별로 매개변수 , 리턴값 등 어떻게 사용해야하는지 주석 달아주세요.

#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"

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

int got_packet(const u_char* packet, u_char** got_ip)
{
    //리턴 0일때는 이후행동없이 다음패킷 보기 1일때는 ip검사진행
    const MAC *mac;
    const IP *ip;
    const TCP *tcp;
    const char *payload; /* Packet payload */

    u_int size_ip, size_tcp;

    // MAC 주소
    mac = (MAC*)(packet);

    // IP 주소
    ip = (IP*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    *got_ip = inet_ntoa(ip->ip_dst);

    // TCP 주소
    tcp = (TCP*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;


    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	if ( strncmp( payload , "GET / HTTP/" , 11 ) != 0 ) {
        if(tcp->th_flags == TH_SYN)
        {
            //출력부분
            printf("src MAC: ");
            for (int i = 0; i < ETHER_ADDR_LEN; i++)
                printf("%02x ", mac->ether_shost[i]);
            puts("");

            printf("dst MAC: ");
            for (int i = 0; i < ETHER_ADDR_LEN; i++)
                printf("%02x ", mac->ether_dhost[i]);
            puts("");

            
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            

            printf("src PORT: %d\n", ntohs(tcp->th_sport));
            printf("dst PORT: %d\n", ntohs(tcp->th_dport));

            printf("flag = %x\n",tcp->th_flags);
            return 1;
        }
		return 0;
	}

    //출력부분
    printf("src MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%02x ", mac->ether_shost[i]);
    puts("");

    printf("dst MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%02x ", mac->ether_dhost[i]);
    puts("");

    
    printf("src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
    

    printf("src PORT: %d\n", ntohs(tcp->th_sport));
    printf("dst PORT: %d\n", ntohs(tcp->th_dport));

    // print payload data .
	printf("INFO: payload = %s .\n" , payload );

    char *host_data = NULL;
	char *host_data_end = NULL;
	int host_data_len = 0;
	char host_data_str[256] = { 0x00 };

    host_data = strstr(payload , "Host: ");
	if ( host_data != NULL ) {
		host_data += 6;
	
		host_data_end = strstr ( host_data , "\r\n" );
		
		host_data_len = host_data_end - host_data ;
		
		strncpy(host_data_str , host_data , host_data_len );
		
		//char *host_data = strstr(payload , "Host: ");
		// print host_data string .
		printf("INFO: host_data_str = %s .\n" , host_data_str );
		
	} else {
		return 0;
	}

    //host_data_str을 db검사하여 있는 url이라면 발송 
    sendraw(packet , sendraw_mode);

    return 0;

}