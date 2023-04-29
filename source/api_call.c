#include "../header/api_call.h"

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
int api_call(CURL * hnd,char * ip_str)
{
   
    printf("1\n");
    struct MemoryStruct chunk;
    chunk.memory = (char *) malloc(1);
    chunk.size = 0;
    char url_str[100] = "https://api.criminalip.io/v1/feature/ip/malicious-info?ip=";
    
    strcat(url_str,ip_str);
   
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_URL, url_str);
 
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, "x-api-key:fDetUQuC3N2558hR1JqT3cqhwzIIGa1FjFxmclo5EQa209CoF41XQMyGbEBz");

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

  
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_to_memory_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *) &chunk);
    


  
    CURLcode ret = curl_easy_perform(hnd);
    
    
    json_object *jobj,*is_malobj;
    jobj = json_tokener_parse(chunk.memory);
    is_malobj = json_object_object_get(jobj, "is_malicious");
   
    

    
    free(chunk.memory);
    return json_object_get_boolean(is_malobj);
}