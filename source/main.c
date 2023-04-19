//main함수 진행될 파일

#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"
#include <stdio.h>
#include <curl/curl.h>
int main()
{

    CURL *hnd = curl_easy_init(); 
    
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/ip_addresses/177.154.84.34");

    struct curl_slist *headers = NULL;
   
    headers = curl_slist_append(headers, "accept: application/json");
   printf("55\n");
   while(headers != NULL)
   {
      printf("%s\n",headers->data);
      headers = headers->next;
   }
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    

}