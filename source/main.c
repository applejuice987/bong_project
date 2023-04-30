// main함수 진행될 파일


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../header/py_call.h"
#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"
#include "../header/api_call.h"
int main()
{

    CURL *hnd = curl_easy_init();
    int is_mal = api_call(hnd,"196.200.150.3");

    printf("malli :%d\n",is_mal);
    if(is_mal)
        py_call();

    curl_easy_cleanup(hnd);
}



