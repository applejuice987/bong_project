#include "include/curl/curl.h" 
#include "include/json/json.h"

struct MemoryStruct {
    char *memory;
    size_t size;
};

int api_call(CURL * ,char * );
size_t write_to_memory_callback(void *, size_t , size_t, void *);
