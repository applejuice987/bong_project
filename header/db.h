//db.c 에 있는 함수 원형 등 적으면됨.
#include  "../header/include/mysql/mysql.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef DB_H
#define DB_H

typedef struct {
    const char* host_ip;
    const char* user_id;
    const char* passwd;
    const char* db_name;
    const char* table_name;
    int port;
    const char* socket;
} db_info;

// MYSQL 구조체 초기화 실패 시 처리
void resetCheck(MYSQL **mysql);

// mariadb 접속(연결)
MYSQL* mariadbConnect(db_info info);

// IP 필터링 쿼리 실행
int ipFilteringQuery(MYSQL* mysql, db_info info,u_char *ip_str);

// SELECT 쿼리 실행
void selectQuery(MYSQL *mysql, int ip_exists);

#endif
