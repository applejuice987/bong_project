#include "../header/api_call.h"
#include "../header/db.h"

#include <string.h>
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
// 공식사이트 https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html 
// 공식사이트에도 위함수 코드에 대한 자세한 내용은없음. 
// "받아온내용을 변수에 넣기위한 콜백함수" 정도로만 생각하면될듯.

int api_call(CURL * hnd, u_char * ip_str) //api 호출 함수
{
   
    struct MemoryStruct chunk; //응답내용 받을 변수
    chunk.memory = (char *) malloc(1); 
    chunk.size = 0;

    char url_str[100] = "https://api.criminalip.io/v1/feature/ip/malicious-info?ip=";
    //rest api 호출에 사용될 url이 담길 배열

    strcat(url_str,ip_str);
    //넘겨받은 ip값을 url 뒤에 붙임.

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    //요청할 메소드 지정 우리가 사용할 api는 get 방식이므로 이에맞게 설정
    curl_easy_setopt(hnd, CURLOPT_URL, url_str);
    //접속할 url지정 위에서 선언한 url_str 배열을 인자로 사용함.
 
    struct curl_slist *headers = NULL;
    //전송하면서 담길 헤더정보를 담을 변수 생성.
    headers = curl_slist_append(headers, "accept: application/json");
    //json형식으로 전송
    headers = curl_slist_append(headers, "x-api-key:fDetUQuC3N2558hR1JqT3cqhwzIIGa1FjFxmclo5EQa209CoF41XQMyGbEBz");
    //api에 사용될 인증키 설정

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);
    //만든 헤더를 적용함.
  
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_to_memory_callback);
    //api 응답이 기본적으로는 stdout이라 화면출력되는데 위 설정시 콜백함수로 보내지도록됨.

    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *) &chunk);
    //콜백함수에 void *userp 인자로 보내짐. 결론적으로는 chunk에 api응답이 담김.
    


  
    CURLcode ret = curl_easy_perform(hnd);
    //curl 요청 실행. 응답코드가 ret에 담김.
    //printf("111111111 : %s\n\n\n", chunk.memory);
    json_object *jobj,*is_malobj, *is_vpnobj, *is_canremoteobj;
    jobj = json_tokener_parse(chunk.memory);
    //받아온 json 파싱
    is_malobj = json_object_object_get(jobj, "is_malicious");
    is_vpnobj = json_object_object_get(jobj, "is_vpn");
    is_canremoteobj = json_object_object_get(jobj, "can_remote_access");

    //우리가 필요한 is_json부분 가져옴
   
    //printf("dataType : %s\n", json_object_get_string(is_malobj));

    char is_malval, is_vpnval, is_canremoteval;
    if      (json_object_get_boolean(is_malobj) == true)        is_malval = 'T';
    else if (json_object_get_boolean(is_malobj) == false)       is_malval = 'F';
    if      (json_object_get_boolean(is_vpnobj) == true)        is_vpnval = 'T';
    else if (json_object_get_boolean(is_vpnobj) == false)       is_vpnval = 'F';
    if      (json_object_get_boolean(is_canremoteobj) == true)  is_canremoteval = 'T';
    else if (json_object_get_boolean(is_canremoteobj) == false) is_canremoteval = 'F';
    
    // MYSQL 구조체
    MYSQL* mysql = NULL;

    // DB 정보
    db_info info = {
        .host_ip = "127.0.0.1",
        .user_id = "bong",
        .passwd = "1234",
        .db_name = "project",
        .table_name = "ip_table",
        .port = 3306,
        .socket = NULL
    };

    // DB 연결
    mysql = mariadbConnect(info);

    // SQL 명령문 세팅
    char query_string[256];
    sprintf(query_string , 
		"insert into ip_table "
		"(ip_str, is_malicious, is_vpn, can_remote_access) "
		"values "
		"('%s', '%c', '%c', '%c')" ,
        ip_str, is_malval, is_vpnval, is_canremoteval
	);

    // SQL 실제 입력
    mysql_query(mysql, query_string);

    mysql_close(mysql);

    free(chunk.memory);
    //메모리 반환
    return json_object_get_boolean(is_malobj);
    //불리안값 형태로 리턴. 악의적이라면 true 즉 1 정상이라면 false 즉 0
}