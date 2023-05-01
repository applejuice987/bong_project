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

    db_info info = {
        .host_ip = "127.0.0.1",
        .user_id = "bong",
        .passwd = "1234",
        .db_name = "project",
        .table_name = "ip_table",
        .port = 3306,
        .socket = NULL
    };
    CURL *hnd;
    MYSQL* mysql;
    int is_mal,is_exist;
    char ip_str[] = "196.200.150.3";

    // Mariadb 접속(연결)
    mysql = mariadbConnect(info);
    // MYSQL 구조체 초기화 확인
    resetCheck(&mysql);

    // Mariadb 접속 성공시 실행
    if (mysql) {
        // IP 필터링 쿼리 실행
        is_exist = ipFilteringQuery(mysql, info,ip_str);\
        // 연결 종료
        mysql_close(mysql);
    }

    if(is_exist)
    {
        //존재한다면 바로 파이썬모듈 콜해서 우회
        printf("ip가 db에있음\n");
        py_call();
    }
    else
    {
        //존재하지않는다면 api호출해서 질의
        printf("ip가 db에없음\n");
        hnd = curl_easy_init();
        is_mal = api_call(hnd,ip_str);

        printf("malli :%d\n",is_mal);
        //악의적이라면
        if(is_mal)
            py_call();
            //이 if안에 db에 ip추가내용 들어가야함.

        curl_easy_cleanup(hnd);
    }
    
}



