#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "memc_connector.h"
#include "analyse_packet.h"
#include "ac_automation.h"



int main(int argc, char *argv[])
{
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
	do 
	{
		status = pcap_next_ex(handle, &pktHeader, &data);
		if (status != 1) break;
		int ret = analyse_packet(pktHeader, data);
		if (ret == -2)
			puts("ignore");
		else if (ret == -1)
			puts("not tcp");
		else if (ret == 0)
			puts("tcp unknow");
		else if (ret == 1)
			puts("tcp know");
	}while (status==1);
#ifdef TEST	
	for (int i = 0; i < 3; i++)
	pcap_dump_close(dumper[i]);
#endif
	return 0;
}

