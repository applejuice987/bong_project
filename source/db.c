//db관련된 내용들 들어갈 소스 파일 
//함수별로 매개변수 , 리턴값 등 어떻게 사용해야하는지 주석 달아주세요.
#include "../header/db.h"

// MYSQL 구조체 초기화 실패 시 처리
void resetCheck(MYSQL **mysql){
    if (!*mysql) {
            puts("init faild, out of memory?");
            EXIT_FAILURE;
        }
}

MYSQL* mariadbConnect(const char *host_ip, const char *table_name) {
    MYSQL *mysql = mysql_init(NULL);
    if (!mysql_real_connect(
            mysql,
            host_ip,      // host ip
            "lee",        // user_id
            "1234",       // passwd
            table_name,  // 접속대상 db
            3306,         // mariadb port
            NULL,         // socket
            0)) {
        // 실패시, 오류 내용 출력
        printf("%s\n", mysql_error(mysql));
        return NULL;
    }
    // mysql 연결 반환
    return mysql;
}

// IP 주소가 DB의 존재 여부 확인
int selectQuery(MYSQL *mysql, const char *query) {
    if (mysql_query(mysql, query)) {
        printf("Query failed: %s\n", mysql_error(mysql));
        return 0;
    } else {
        MYSQL_RES *result = mysql_store_result(mysql);
        if (!result) {
            printf("Couldn't get results set: %s\n", mysql_error(mysql));
            return 0;
        } else {
            int ip_exists = mysql_num_rows(result) > 0;
            mysql_free_result(result);
            return ip_exists;
        }
    }
}
