#ifndef __SHCD_STORAGE_H__
#define __SHCD_STORAGE_H__

#include <shardcache.h>

#define MAX_STORAGE_OPTIONS 256
#define MAX_OPTIONS_STRING_LEN 2048

typedef struct shcd_storage_s shcd_storage_t;

shcd_storage_t * shcd_storage_init(char *storage_type, char *options_string, char *plugins_dir);

void shcd_storage_destroy(shcd_storage_t *st);

shardcache_storage_t *shcd_storage_get(shcd_storage_t *st);

#endif