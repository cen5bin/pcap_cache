#include "memc_connector.h"

static memcached_st *memc;
static memcached_server_st *servers;
static int memcached_connected = -1;

int memcached_connect_to_server(char *hostname, int port)
{
	memc = memcached_create(NULL);
	servers = memcached_server_list_append(NULL, hostname, port, NULL);
	memcached_return rc;
	rc = memcached_server_push(memc, servers);
	memcached_connected = 0;
	if (rc == MEMCACHED_SUCCESS) 
		return 0;
	return -1;
}

//返回0表示成功，-1表示失败
int memcached_set_value(char *key, size_t key_len, char *value, size_t value_len, uint32_t flag)
{
	if (memcached_connected == -1)
	{
		if (memcached_connect_to_server("localhost", 11211) == -1)
			return -1;
	}
	memcached_return rc;
	rc = memcached_set(memc, key, key_len, value, value_len, 0, flag);
	if (rc == MEMCACHED_SUCCESS)
		return 0;
	return -1;
}

int memcached_get_value(char *key, size_t key_len, char **value, size_t *value_len, uint32_t *flag) 
{
	if (memcached_connected == -1)
	{
		if (memcached_connect_to_server("localhost", 11211) == -1)
			return -1;
	}
	memcached_return rc;
	*value = memcached_get(memc, key,key_len, value_len, flag, &rc);
	if (rc == MEMCACHED_SUCCESS)
		return 0;
	return -1;
}

int memcached_append_value(char *key, size_t key_len, char *value, size_t value_len, uint32_t flag)
{
	if (memcached_connected == -1)
	{
		if (memcached_connect_to_server("localhost", 11211) == -1)
			return -1;
	}
	memcached_return rc;
	rc = memcached_append(memc, key, key_len, value, value_len, 0, flag);
	if (rc == MEMCACHED_SUCCESS)
		return 0;
	return -1;
}

int memcached_key_exist(char *key, size_t key_len)
{
	if (memcached_exist(memc, key, key_len) == MEMCACHED_SUCCESS)
		return 0;
	return -1;
}
