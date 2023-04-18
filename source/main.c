//main함수 진행될 파일
#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"

int main()
{   
    // IP 주소 입력
    const char* host_ip = "192.168.64.6";

    // Mariadb 접속(연결)
    MYSQL* mysql = mariadbConnect(host_ip);

    // MYSQL 구조체 초기화 확인
    resetCheck(&mysql);

    // Mariadb 접속 성공시 실행
    if (mysql) {
        // SELECT 쿼리 실행
        selectQuery(mysql);

        // 연결 종료
        mysql_close(mysql);
    }

    return EXIT_SUCCESS;
}
