#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "memc_connector.h"


//struct compact_ip_hdr aaa;

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
#pragma pack()

#pragma pack(1)
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

// 以太网协议帧协议类型
#define PKT_TYPE_IP 0x0800
#define PKT_TYPE_ARP 0x0806
#define PKT_TYPE_RARP 0x8035 
#define PKT_TYPE_IPV6 0x86dd

//以太网帧解析
int get_pkt_type(u_char *data); //以太网帧协议类型
void get_ip_pkt(u_char *data, int len, u_char **ip_data, int *ip_data_len); //获取IP数据包,返回值在ipData中

////////////////////////////////////////////////////////////////////////////////////////
// IP层协议类型
#define IP_TYPE_ICMP 1
#define IP_TYPE_IGMP 2
#define IP_TYPE_TCP 6
#define IP_TYPE_EGP 8
#define IP_TYPE_UDP 17
#define IP_TYPE_OSPF 89

//IP数据包解析
void get_tcp_pkt(u_char *ip_data, int len, u_char **tcp_data, int *tcp_len); //获取tcp数据包

///////////////////////////////////////////////////////
//TCP数据包解析
int get_src_port(u_char *data); //源端口
int get_dest_port(u_char *data); //目的端口
void get_content(u_char *data, int len, char **content, int *content_len);


int main(int argc, char *argv[])
{
#if 0
	char *key = "aaa";
	char *value = "zzz";
	memcached_set_value(key, strlen(key), value, strlen(value), 0);
	uint32_t flag = 0;
	char *s = NULL;
	size_t len = 0;
	memcached_get_value(key, strlen(key), &s, &len, &flag);
	printf("value %s len %ld flag %d\n", s, len, flag);
#endif
	if (argc < 2)
	{
		puts("please input a filename!");
		return 0;
	}

	char errBuffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(argv[1], errBuffer);
	if (handle == NULL)
	{
		printf("open file %s failed\n", argv[1]);
		return 0;
	}

	struct pcap_pkthdr *pktHeader;
	u_char *data = NULL;
	int status;
	int cnt = 0;
	do 
	{
		status = pcap_next_ex(handle, &pktHeader, &data);
		if (status != 1) break;
		int eth_type = get_pkt_type(data);
		if (eth_type != PKT_TYPE_IP)
			continue;
		if (++cnt == 20)
		break;

		u_char *ip_data = NULL;
		int ip_data_len = 0;
		get_ip_pkt(data, pktHeader->caplen, &ip_data, &ip_data_len);
		struct compact_ip_hdr *ip_hdr = (struct compact_ip_hdr *)ip_data;


		int protocol = ip_hdr->protocol; 
		if (protocol == IP_TYPE_TCP)
		{
			u_int32_t srcip = ntohl(ip_hdr->saddr);//get_pkt_srcip(ip_data);
			u_int32_t destip = ntohl(ip_hdr->daddr);//get_pkt_destip(ip_data);	
			u_char *tcp_data = NULL;
			int tcp_len = 0;
			get_tcp_pkt(ip_data, ip_data_len, &tcp_data, &tcp_len);
			struct compact_tcp_hdr *tcp_hdr = (struct compact_tcp_hdr *)tcp_data;
			u_int16_t src_port = ntohs(tcp_hdr->src_port);
			u_int16_t dest_port = ntohs(tcp_hdr->dest_port);
			char *content = NULL;
			int content_len = 0;
			get_content(tcp_data, tcp_len, &content, &content_len);
			printf("%d\n", content_len);
			puts(content);
		}
		else if (protocol == IP_TYPE_UDP)
		{
		}
		else 
			continue;

	}while (status==1);
	
	return 0;
}

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
	printf("tcp_len %d\n", tcp_header_len);
	int tcp_content_len = len - tcp_header_len;
	*content_len = tcp_content_len;
	*content = (char *)data + (tcp_header_len-0);
}
