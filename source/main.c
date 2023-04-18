//main함수 진행될 파일

#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"

int main()
{

    MYSQL* mysql = mysql_init(NULL);

	resetCheck(&mysql);
    mariadbConnect(&mysql);
	
	mysql_close(mysql);
	return EXIT_SUCCESS;

}