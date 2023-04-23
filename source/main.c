//main함수 진행될 파일
#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"

int main() {
    const char *ip_address = "192.168.64.6";
    const char *table_name = "employees";
    MYSQL *mysql = mariadbConnect(ip_address,table_name);

    if (mysql) {
        // IP 주소 존재 여부 확인
        
        char query[256];
        snprintf(query, sizeof(query), "SELECT * FROM %s WHERE ip_address = '%s'", table_name, ip_address);

        int ip_exists = selectQuery(mysql, query);

        // 연결 종료
        mysql_close(mysql);
    }

    return EXIT_SUCCESS;
}


