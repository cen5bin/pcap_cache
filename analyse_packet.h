#pragma once

//#define TEST

#ifdef TEST
extern pcap_dumper_t *dumper[3] = {NULL, NULL, NULL};
#endif

int before_analyse();
int analyse_packet(struct pcap_pkthdr * header, u_char *data);
