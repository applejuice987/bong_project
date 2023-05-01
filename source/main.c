<<<<<<< HEAD
// main함수 진행될 파일


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../header/py_call.h"
=======
// main 함수 진행될 파일
>>>>>>> jeongy01
#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"
#include "../header/api_call.h"
int main()
{   
    // DB 정보 입력
    db_info info = {
        .host_ip = "192.168.64.6",
        .user_id = "lee",
        .passwd = "1234",
        .db_name = "employees",
        .table_name = "dept_manager",
        .port = 3306,
        .socket = NULL
    };

<<<<<<< HEAD
    CURL *hnd = curl_easy_init();
    int is_mal = api_call(hnd,"196.200.150.3");

    printf("malli :%d\n",is_mal);
    if(is_mal)
        py_call();

    curl_easy_cleanup(hnd);
}



=======
    // Mariadb 접속(연결)
    MYSQL* mysql = mariadbConnect(info);

    // MYSQL 구조체 초기화 확인
    resetCheck(&mysql);

    // Mariadb 접속 성공시 실행
    if (mysql) {
        // IP 필터링 쿼리 실행
        ipFilteringQuery(mysql, info);

        // 연결 종료
        mysql_close(mysql);
    }

    return EXIT_SUCCESS;
}
>>>>>>> jeongy01
