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

// mariadb 접속(연결)
MYSQL* mariadbConnect(const char *host_ip)
{
    MYSQL *mysql = mysql_init(NULL);
    if (!mysql_real_connect(
            mysql
            , host_ip      // host ip
            , "lee"        // user_id
            , "1234"       // passwd
            , "employees"  // 접속대상 db
            , 3306         // mariadb port
            , NULL         // socket
            , 0))
    {
        // 실패시, 오류 내용 출력
        printf("%s\n", mysql_error(mysql));
        return NULL;
    }
    // mysql 연결 반환
    return mysql;
}

// SELECT 쿼리 실행
void selectQuery(MYSQL *mysql)
{
    if (mysql_query(mysql, "select * from dept_manager"))
    {
        // 실패
        printf("Query failed: %s\n", mysql_error(mysql));
    }
    else
    {
        // 성공
        MYSQL_RES *result = mysql_store_result(mysql);
        unsigned int num_fields = mysql_num_fields(result);

        if (!result) {
                    printf("Couldn't get results set : %s\n", mysql_error(mysql));
                }
                else {
                    MYSQL_ROW row;
                    // mysql_fetch_row() >> 더이상 가져올 row가 없으면 NULL반환.
                    // NULL==0
                    // if(0) >> false 
                    // if(!0) >> true
                    MYSQL_FIELD* field; 
                    while ((field = mysql_fetch_field(result))) {
                        printf("%s ", field->name);
                    }
                    puts("");

                    while ((row = mysql_fetch_row(result))) {
                        for (unsigned int i = 0; i < num_fields; i++) {
                            printf("%s ", row[i]);
                        }
                        puts("");
                    }
                    mysql_free_result(result);
                }
    }
}