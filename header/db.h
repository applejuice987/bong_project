//db.c 에 있는 함수 원형 등 적으면됨.
#include  "../header/include/mysql/mysql.h"
#include <stdio.h>
#include <stdlib.h>

void resetCheck(MYSQL **mysql);
MYSQL* mariadbConnect(const char *host_ip);
void selectQuery(MYSQL *mysql);


