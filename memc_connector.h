#pragma once

#include <libmemcached/memcached.h>

int memcached_connect_to_server(char *hostname, int port);

//返回0表示成功，-1表示失败
int memcached_set_value(char *key, size_t key_len, char *value, size_t value_len, uint32_t flag);
int memcached_get_value(char *key, size_t key_len, char **value, size_t *value_len, uint32_t *flag);

int memcached_key_exist(char *key, size_t key_len); //返回0表示key存在，返回-1不存在
