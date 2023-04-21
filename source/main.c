// main함수 진행될 파일

#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"


#include "../header/include/curl/curl.h" 
#include "../header/include/json/json.h"
//#include <curl/curl.h>
//#include <json-c/json.h>

#include <stdio.h>
int main()
{

    CURL *hnd = curl_easy_init();


    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/ip_addresses/177.154.84.34");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, "x-apikey: c58bade78504ce953865e8cfc05ec4b11cdc144a8f882afd0beb0b20885f9df7");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    

    



    CURLcode ret = curl_easy_perform(hnd);

    printf("%d",ret);
}

//c58bade78504ce953865e8cfc05ec4b11cdc144a8f882afd0beb0b20885f9df7