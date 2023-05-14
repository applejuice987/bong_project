void *func2(void *arg)
{
  u_char *got_ip;
    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_t *handle;
    CURL *hnd;
    MYSQL* mysql;
    int is_mal,is_exist;
    int flag;
    db_info info = {
        .host_ip = "127.0.0.1",
        .user_id = "bong",
        .passwd = "1234",
        .db_name = "project",
        .table_name = "ip_table",
        .port = 3306,
        .socket = NULL
    };
    
    packet_capture_setter(&handle,2);

    // 테스트
    // pcap_next_ex(handle, &header, &packet);
    // got_packet(packet, &got_ip);
   
    while(pcap_next_ex(handle, &header, &packet) == 1)
    {
    
        flag = got_packet(packet, &got_ip);
        if (flag==0)
            continue;
    // [용도] packet에 정보를 전달하는 함수
    // [인자] handle, packet의 header 구조체, packet 정보
    // [성공] 1
    // [실패] 시간초과 0, 실패 PCAP_ERROR

         printf("got_ip: %s \n", got_ip);
    
    
        mysql = mariadbConnect(info); // Mariadb 접속(연결)
   
        resetCheck(&mysql); // MYSQL 구조체 초기화 확인

        if (mysql) { // Mariadb 접속 성공시 실행
        
            is_exist = ipFilteringQuery(mysql, info,got_ip); // IP 필터링 쿼리 실행
            mysql_close(mysql); // 연결 종료
        }

        if(is_exist) //존재한다면 바로 파이썬모듈 콜해서 우회
        {
       
            printf("ip가 db에있음\n");
            py_call();
        }   
        else //존재하지않는다면 api호출해서 질의
        {
        
            printf("ip가 db에없음\n");
            hnd = curl_easy_init();
            is_mal = api_call(hnd,got_ip);

            printf("malli :%d\n",is_mal);
            
            if(is_mal) //악의적이라면
                py_call();
                //이 if안에 db에 ip추가내용 들어가야함.

            curl_easy_cleanup(hnd);
        }
    }
    pcap_close(handle);
    
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
        printf("%s\n",*got_ip);
        printf("%s\n","127.0.0.1");
        printf("!!!!!!!!!!!!!!!!!!!\n!!!!!!!!!!!!!!!!!!!!\n");
        if(tcp->th_flags == TH_SYN && strcmp(*got_ip,"127.0.0.1") != 0)
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



