// db.c 파일
#include "../header/db.h"

// MYSQL 구조체 초기화 실패 시 처리
void resetCheck(MYSQL **mysql){
    if (!*mysql) {
        puts("init faild, out of memory?");
        exit(EXIT_FAILURE);
    }
}

// mariadb 접속(연결)
MYSQL* mariadbConnect(db_info info)
{
    MYSQL *mysql = mysql_init(NULL);
    if (!mysql_real_connect(
            mysql
            , info.host_ip     // host ip
            , info.user_id     // user_id
            , info.passwd      // passwd
            , info.db_name     // 접속대상 db
            , info.port        // mariadb port
            , info.socket      // socket
            , 0))
    {
        // 실패시, 오류 내용 출력
        printf("%s\n", mysql_error(mysql));
        return NULL;
    }
    // mysql 연결 반환
    return mysql;
}

// IP 필터링 쿼리 실행
int ipFilteringQuery(MYSQL* mysql, db_info info,char *ip_str) {
    char query[100];
    sprintf(query, "SELECT * FROM %s WHERE ip_str = '%s'", info.table_name,ip_str);
    if (mysql_query(mysql, query)) {
        // 실패
        printf("Query failed: %s\n", mysql_error(mysql));
        return 0;
    }
    else {
        // 성공
        MYSQL_RES *result = mysql_store_result(mysql);
        int exist = mysql_num_rows(result) > 0;
        mysql_free_result(result);
        return exist;
    }
}
