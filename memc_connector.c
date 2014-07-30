#include "memc_connector.h"

static memcached_st *memc;
static memcached_server_st *servers;
static int memcached_connected = -1;

void memcached_connect_to_server(char *hostname, int port)
{
	memc = memcached_create(NULL);
	servers = memcached_server_list_append(NULL, hostname, port, NULL);
	memcached_return rc;
	rc = memcached_server_push(memc, servers);
}

//返回0表示成功，-1表示失败
int memcached_set_value(char *key, size_t key_len, char *value, size_t value_len, uint32_t flag)
{
	memcached_return rc;
	rc = memcached_set(memc, key, key_len, value, value_len, 0, flag);
	if (rc == MEMCACHED_SUCCESS)
		return 0;
	return -1;
}
int memcached_get_value(char *key, size_t key_len, char **value, size_t *value_len, uint32_t *flag) 
{
	memcached_return rc;
	*value = memcached_get(memc, key,key_len, value_len, flag, &rc);
	if (rc == MEMCACHED_SUCCESS)
		return 0;
	return -1;
}
