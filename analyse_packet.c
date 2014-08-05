#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "memc_connector.h"
#include "ac_automation.h"

#define PKT_TYPE_IP 0x0800
#define IP_TYPE_TCP 6
#define IP_TYPE_UDP 17

#pragma pack(1)
struct compact_ip_hdr {
	u_int8_t	ihl:4,
	version:4;
	u_int8_t	tos;
	u_int16_t	tot_len;
	u_int16_t	id;
	u_int16_t	frag_off;
	u_int8_t	ttl;
	u_int8_t	protocol;
	u_int16_t	check;
	u_int32_t	saddr;
	u_int32_t	daddr;
};
struct compact_tcp_hdr {
	u_int16_t src_port;
	u_int16_t dest_port;
	u_int32_t seqnum;
	u_int32_t acknum;
	u_int16_t infos;
			  //tol_len:4,
			  //reserved:6,
			  //urg:1,
			  //ack:1,
			  //psh:1,
			  //pst:1,
			  //syn:1,
			  //fin:1;
	u_int16_t win_size;
	u_int16_t check;
	u_int16_t urgent_pointer;

};
#pragma pack()


int before_analyse()
{
	return 0;
}

//以太网帧协议类型
int get_pkt_type(u_char *data)
{
	return (data[12]<<8)+data[13];
}

void get_ip_pkt(u_char *data, int len, u_char **ip_data, int *ip_data_len)
{
	int ip_pkt_len = len - 6 * 2 - 2;
	*ip_data_len = ip_pkt_len;
	*ip_data = data+6*2+2;;
}


void get_tcp_pkt(u_char *ip_data, int len, u_char **tcp_data, int *tcp_len)
{
	int ip_header_len = (ip_data[0] & 0x0F) * 4;
	int ip_data_len = len - ip_header_len;
	*tcp_len = ip_data_len;
	*tcp_data = ip_data+ip_header_len;
}


void get_content(u_char *data, int len, char **content, int *content_len) 
{
	struct compact_tcp_hdr *header = (struct compact_tcp_hdr *)data;
	int tcp_header_len = ((ntohs(header->infos)&0xF000)>>12) * 4;
	int tcp_content_len = len - tcp_header_len;
	*content_len = tcp_content_len;
	*content = (char *)data + (tcp_header_len-0);
}

char* cal_key(uint32_t src_ip, uint16_t src_port,  uint32_t dest_ip, uint16_t dest_port)
{
	static const int BUFFER_MAX_SIZE = 128;
	static char buffer[BUFFER_MAX_SIZE];
	uint32_t ip1, ip2;
	uint16_t port1, port2;
	if (src_ip > dest_ip)
		ip1 = src_ip, ip2 = dest_ip, port1 = src_port, port2 = dest_port;
	else if (src_ip < dest_ip)
		ip2 = src_ip, ip1 = dest_ip, port2 = src_port, port1 = dest_port;
	else if (src_port >= dest_port)
		ip1 = src_ip, ip2 = dest_ip, port1 = src_port, port2 = dest_port;
	snprintf(buffer, sizeof(char)*BUFFER_MAX_SIZE, "%u:%d#%u:%d", src_ip, src_port, dest_ip, dest_port);
	return buffer;
}

#ifdef TEST
static pcap_dumper_t *dumper[3] = {NULL, NULL, NULL};
void write_to_pcap_file(int type, struct pcap_pkthdr *header, u_char *data)
{
	if (dumper[type+1] == NULL)
	{
		char *filename = "";
		if (type == -1) filename = "notTCP.pcap";
		else if (type == 0) filename = "unknowTCP.pcap";
		else if (type == 1) filename = "knowTCP.pcap";
		pcap_t *p = pcap_open_dead(DLT_EN10MB, 65536);
		dumper[type+1] = pcap_dump_open(p, filename);
	}
	pcap_dump((u_char *)dumper[type+1], header, data);
}
#endif 

//返回值 -2表示不是ip协议，-1表示非tcp，包括udp等， 0表示tcp协议但是上层unknow，1表示tcp协议并且上层已经识别出协议
int analyse_packet(struct pcap_pkthdr * header, u_char *data)
{
	int eth_type = get_pkt_type(data);
	if (eth_type != PKT_TYPE_IP) 
		return -2;

	u_char *ip_data = NULL;
	int ip_data_len = 0;
	get_ip_pkt(data, header->caplen, &ip_data, &ip_data_len);
	struct compact_ip_hdr *ip_hdr = (struct compact_ip_hdr *)ip_data;

	int protocol = ip_hdr->protocol; 
	if (protocol != IP_TYPE_TCP) {
#ifdef TEST
		write_to_pcap_file(-1, header, data);	
#endif
		return -1;
	}
	u_int32_t src_ip = ntohl(ip_hdr->saddr);
	u_int32_t dest_ip = ntohl(ip_hdr->daddr);	

	u_char *tcp_data = NULL;
	int tcp_len = 0;
	get_tcp_pkt(ip_data, ip_data_len, &tcp_data, &tcp_len);
	struct compact_tcp_hdr *tcp_hdr = (struct compact_tcp_hdr *)tcp_data;
	u_int16_t src_port = ntohs(tcp_hdr->src_port);
	u_int16_t dest_port = ntohs(tcp_hdr->dest_port);
	char *key = cal_key(src_ip, src_port, dest_ip, dest_port);
	if (memcached_key_exist(key, strlen(key)) == 0)
	{
		size_t len = 0;
		char *value = NULL;
		uint32_t flag = 0;
		int ret	= memcached_get_value(key, strlen(key), &value, &len, &flag);
		if (ret == -1) return -2;
		int type = *(int *)value;
		if (type == 1) 
		{
#ifdef TEST
			write_to_pcap_file(1, header, data);
#endif
			return 1;
		}
		else if (type == 0)
		{
			memcached_append_value(key, strlen(key), (char *)data, header->caplen, 0);
#ifdef TEST
			write_to_pcap_file(0, header, data);
#endif
			return 0;
		}
		return -2;
	}
	else 			
	{
		int type = 0;
		if (src_port == 80 || dest_port == 80)	
			type = 1;
		memcached_set_value(key, strlen(key), (char *)&type, sizeof(type), 0);
		if (type == 0) 
		{
			memcached_append_value(key, strlen(key), (char *)data, header->caplen, 0);
#ifdef TEST
			write_to_pcap_file(0, header, data);
#endif
		}
		else 
		{
#ifdef TEST
			write_to_pcap_file(1, header, data);
#endif
		}
		return 0;
	}
	return 0;
	char *content = NULL;
	int content_len = 0;
	get_content(tcp_data, tcp_len, &content, &content_len);
	printf("%d\n", content_len);
	puts(content);
}
