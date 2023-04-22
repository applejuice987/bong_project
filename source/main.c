// main함수 진행될 파일

#include "../header/db.h"
#include "../header/pcapcap.h"
#include "../header/pcapmodu.h"


#include "../header/include/curl/curl.h" 
#include "../header/include/json/json.h"
//#include <curl/curl.h>
//#include <json-c/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct MemoryStruct {
    char *memory;
    size_t size;
};

size_t write_to_memory_callback(void *buffer, size_t size, size_t nmemb, void *userp) {

    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;
    char *ptr = (char *) realloc(mem->memory, mem->size + realsize + 1);

    if(!ptr) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), buffer, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int main()
{

    CURL *hnd = curl_easy_init();
    struct MemoryStruct chunk;
    chunk.memory = (char *) malloc(1);
    chunk.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    //curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/ip_addresses/213.226.123.202");
    curl_easy_setopt(hnd, CURLOPT_URL, "https://api.criminalip.io/v1/feature/ip/malicious-info?ip=213.226.123.202");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    //headers = curl_slist_append(headers, "x-apikey: c58bade78504ce953865e8cfc05ec4b11cdc144a8f882afd0beb0b20885f9df7");
    headers = curl_slist_append(headers, "x-api-key:fDetUQuC3N2558hR1JqT3cqhwzIIGa1FjFxmclo5EQa209CoF41XQMyGbEBz");

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_to_memory_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *) &chunk);
    



    CURLcode ret = curl_easy_perform(hnd);
    curl_easy_cleanup(hnd);
    if (chunk.size > 0) {
        printf("111111111 : %s", chunk.memory);
    }
    free(chunk.memory);
}

//c58bade78504ce953865e8cfc05ec4b11cdc144a8f882afd0beb0b20885f9df7