// main함수 진행될 파일

#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"
#include "../header/api_call.h"



#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main()
{

    CURL *hnd = curl_easy_init();
    int is_mal = api_call(hnd,"196.200.150.3");

    printf("malli :%d\n",is_mal);


    curl_easy_cleanup(hnd);
}



