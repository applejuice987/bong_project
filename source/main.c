// main함수 진행될 파일

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "../header/py_call.h"
#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"
#include "../header/api_call.h"
void *func1(void *arg);
void *func2(void *arg);
int main()
{
    

    pthread_t tid1,tid2;

    if(pthread_create(&tid1,NULL,func1,NULL) != 0){
        fprintf(stderr,"thread create error\n");
        exit(1);
    }

    if(pthread_create(&tid2,NULL,func2,NULL)!=0){
        fprintf(stderr,"thread create error\n");
        exit(1);
    }

    pthread_join(tid1,NULL);
    pthread_join(tid2,NULL);
    

    
}

void *func1(void * arg)
{
    //로컬호스트 패킷 캡처부분
    u_char *got_info = NULL;
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
        .table_name = "domain_table",
        .port = 3306,
        .socket = NULL
    };
    packet_capture_setter(&handle, 1);
    puts("\tLocal Packet Capture Set Complete");

    // 테스트
    // pcap_next_ex(handle, &header, &packet);
    // got_packet(packet, &got_ip);
   
    while(pcap_next_ex(handle, &header, &packet) == 1)
    {
        flag = got_packet(packet, &got_info, 1);
        if (flag == 0)
            continue;

        //got_info을 db검사하여 있는 url이라면 발송

        got_info += strlen("Host: ");
        char* host_data_end = strstr(got_info, "\r\n");
        int host_data_len = strlen(got_info) - strlen(host_data_end);
        char got_url[256] = { 0x00 };

        strncpy(got_url, got_info, host_data_len);

        printf("\n\tgot_url = %s\n\n", got_url);

        mysql = mariadbConnect(info); // Mariadb 접속(연결)
   
        resetCheck(&mysql); // MYSQL 구조체 초기화 확인

        char* res_cnt;
        MYSQL_ROW row;
        MYSQL_RES* res;
        
        char query_string[512];
        sprintf(query_string, "SELECT count(*) FROM domain_table WHERE domain_str = '%s'", got_url);
        mysql_query(mysql, query_string);
        
        res = mysql_store_result(mysql);
        if (res == NULL) continue;
        else
        {
            while((row = mysql_fetch_row(res)) != NULL) 
                res_cnt = row[0];
               
            
                
        }
        
        mysql_free_result(res);
        mysql_close(mysql);

        if(strcmp(res_cnt,"1")==0) sendraw(packet, sendraw_mode);        
        else            continue;

    // [용도] packet에 정보를 전달하는 함수
    // [인자] handle, packet의 header 구조체, packet 정보
    // [성공] 1
    // [실패] 시간초과 0, 실패 PCAP_ERROR

    }
    pcap_close(handle);
}

void *func2(void *arg)
{
    u_char *got_info;
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
    
    packet_capture_setter(&handle, 2);
    puts("\tNIC Packet Capture Set Complete");

    // 테스트
    // pcap_next_ex(handle, &header, &packet);
    // got_packet(packet, &got_ip);
   
    while(pcap_next_ex(handle, &header, &packet) == 1)
    {
        flag = got_packet(packet, &got_info, 2);
        if (flag == 0)
            continue;
    // [용도] packet에 정보를 전달하는 함수
    // [인자] handle, packet의 header 구조체, packet 정보
    // [성공] 1
    // [실패] 시간초과 0, 실패 PCAP_ERROR

        printf(" got_ip: %15s |", got_info);
    
        mysql = mariadbConnect(info); // Mariadb 접속(연결)
   
        resetCheck(&mysql); // MYSQL 구조체 초기화 확인

        if (mysql) { // Mariadb 접속 성공시 실행
        
            is_exist = ipFilteringQuery(mysql, info, got_info); // IP 필터링 쿼리 실행
        }

        if(is_exist) //존재한다면 바로 파이썬모듈 콜해서 우회
        {
            printf(" ip가 db에 있습니다 |");
            
            char ch;
            MYSQL_ROW row;
            MYSQL_RES* res;
            
            char query_string[256];
            sprintf(query_string, "SELECT is_malicious FROM ip_table WHERE ip_str = '%s'", got_info);
            mysql_query(mysql, query_string);

            res = mysql_store_result(mysql);

            while((row = mysql_fetch_row(res)) != NULL)   
                   ch = *row[0];

            mysql_free_result(res);
            
            mysql_close(mysql); // 연결 종료

            printf(" is_mal?: %c |\n", ch);

            if(ch == 'T')
            {
                py_call();
                puts("\tpage shutdown");
                continue;
            }
        }   
        else //존재하지않는다면 api호출해서 질의
        {
        
            printf(" ip가 db에 없습니다 |");
            hnd = curl_easy_init();
            is_mal = api_call(hnd, got_info);
            
            if(is_mal) //악의적이라면
                py_call();
                //이 if안에 db에 ip추가내용 들어가야함.

            curl_easy_cleanup(hnd);
        }
    }
    pcap_close(handle);
}






