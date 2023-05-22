//pcap 캡처 관련된 내용들 들어갈 소스 파일 
//함수별로 매개변수 , 리턴값 등 어떻게 사용해야하는지 주석 달아주세요.

#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"

void packet_capture_setter(pcap_t **handle,int mode)
{
    pcap_if_t *dev;
    char dev2[64] = "lo" ; 
    char *errbuf;
    bpf_u_int32 net, mask;
    struct bpf_program fp;
    char *filter_exp = "dst port 80 or dst port 443";
    const u_char* packet;
    
    pcap_findalldevs(&dev, errbuf);
    if (dev == NULL) {
        puts("Device not found");
        return;
	}
    // [용도] network device의 리스트를 구하는 함수
    // [인자] device 리스트를 저장할 포인터, errbuf 에러메세지
    // [성공] 0
    // [실패] PCAP_ERROR = -1

    // dev = pcap_lookupdev(errbuf);
    // [용도] network device를 찾는 함수
    // [인자] errbuf - 실패시 에러메세지
    // [성공] network device의 이름
    // [실패] NULL

    if(mode == 1) dev[0].name=dev2;

	if (pcap_lookupnet(dev[0].name, &net, &mask, errbuf) == -1) {
        puts("Netmask not found");
		net = mask = 0;
        return;
	}
    // [용도] network address, subnetmask를 찾는 함수
    // [인자] device, ip address 저장주소, subnetmask 저장주소, 실패시 에러메세지
    // [성공] 0
    // [실패] PCAP_ERROR = -1

    *handle = pcap_open_live(dev[0].name, BUFSIZ, 1, 1000, errbuf);
    if (*handle == NULL) {
        puts("Device not open");
        return;
	}
    // [용도] packet capture를 위한 handle을 얻는 함수
    // [인자] device, 버퍼사이즈, promiscuous mode, read timeout, 실패시 에러메세지
    // [성공] pcap_t* packet capture handle
    // [실패] NULL


    if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1) {
        puts("Filter not parsed");
        return;
	}
    // [용도] filter를 bpf_program에 저장하는 함수
    // [인자] handle, bpf_program, filter, 최적화, netmask
    // [성공] 0
    // [실패] PCAP_ERROR

    if (pcap_setfilter(*handle, &fp) == -1) {
		puts("Filter not set");
        return;
	}
    // [용도] pcap_compile()에서 저장된 filter를 적용하는 함수
    // [인자] handle, bpf_program
    // [성공] 0
    // [실패] PCAP_ERROR
}

int got_packet(const u_char* packet, u_char** got_info, int mode)
{
    //리턴 0일때는 이후행동없이 다음패킷 보기 1일때는 ip검사진행
    const MAC *mac;
    const IP *ip;
    const TCP *tcp;
    const char *payload; /* Packet payload */

    u_int size_ip, size_tcp, size_payload;

    // MAC 주소
    mac = (MAC*)(packet);

    // IP 주소
    ip = (IP*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
  

    // TCP 주소
    tcp = (TCP*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if(mode==2) //외부 랜카드 검사부분
    {
        *got_info = inet_ntoa(ip->ip_dst); //목적지 ip 얻어냄.
        if(tcp->th_flags == TH_SYN && strcmp(*got_info,"127.0.0.1") != 0) //syn패킷이고 목적지가 자신이 아니라면 1리턴하여 이후진행
        {
            
            //출력부분
            puts("\n\t[Captured Packet INFO]");

            printf("\tsrc MAC: ");
            for (int i = 0; i < ETHER_ADDR_LEN; i++)
                printf("%02x ", mac->ether_shost[i]);

            printf("| src IP: %15s ", inet_ntoa(ip->ip_src));
            printf("| src PORT: %6d\n", ntohs(tcp->th_sport));

            printf("\tdst MAC: ");
            for (int i = 0; i < ETHER_ADDR_LEN; i++)
                printf("%02x ", mac->ether_dhost[i]);

            printf("| dst IP: %15s ", inet_ntoa(ip->ip_dst));
            printf("| dst PORT: %6d\n", ntohs(tcp->th_dport));

            printf("\n\tflag = %x |",tcp->th_flags);

            return 1;
        }//아니라면 0 리턴하여 다음패킷봄
        return 0;
    }
    else  //내부 로컬 호스트 검사부분
    {
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        size_payload = ntohs(ip->ip_len) + (size_ip + size_tcp);
	
	    if ( strncmp( payload , "GET / HTTP/" , 11 ) != 0 ) //get 메세지 인지 확인. 아니라면 0리턴하여 다음패킷봄.
            return 0;

        //출력부분
     

        puts("\n\t[Captured Packet INFO]");

        printf("\tsrc MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++)
            printf("%02x ", mac->ether_shost[i]);

        printf("| src IP: %15s ", inet_ntoa(ip->ip_src));
        printf("| src PORT: %6d\n", ntohs(tcp->th_sport));

        printf("\tdst MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++)
            printf("%02x ", mac->ether_dhost[i]);

        printf("| dst IP: %15s ", inet_ntoa(ip->ip_dst));
        printf("| dst PORT: %6d\n\n", ntohs(tcp->th_dport));

        // print payload data .
        puts("\t[Packet Before Change]");
        print_payload(payload, size_payload);

        //char *host_data = NULL;
        //char *host_data_end = NULL;
        //int host_data_len = 0;
        //char host_data_str[256] = { 0x00 };

        *got_info = strstr(payload , "Host: "); //host 얻어 낼 수 있는지 확인하여 얻어낼 수 있다면 얻어내어 이후진행
        
        if ( *got_info != NULL ) {
            //host_data += strlen("Host: ");
        
            //host_data_end = strstr ( host_data , "\r\n" );
            
            //host_data_len = host_data_end - host_data;
           
            //strncpy(host_data_str, host_data , host_data_len );

            return 1;
            
        } else { //아니라면 0리턴
            return 0;
        }
    }
}