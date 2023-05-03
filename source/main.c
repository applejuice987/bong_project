// main함수 진행될 파일

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../header/py_call.h"
#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"
#include "../header/api_call.h"

int main()
{
    u_char *got_ip;
    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_t *handle;
    CURL *hnd;
    MYSQL* mysql;
    int is_mal,is_exist;

    db_info info = {
        .host_ip = "127.0.0.1",
        .user_id = "bong",
        .passwd = "1234",
        .db_name = "project",
        .table_name = "ip_table",
        .port = 3306,
        .socket = NULL
    };
    
    packet_capture_setter(&handle);

    // 테스트
    pcap_next_ex(handle, &header, &packet);
    got_packet(packet, &got_ip);
   
    // while(pcap_next_ex(handle, &header, &packet) == 1)
    // got_packet(packet, &got_ip);

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

    pcap_close(handle);
    
}






