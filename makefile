all: main.c memc_connector.c analyse_packet.c ac_automation.c ac_automation
	gcc -g -Wall -o run.o  main.c memc_connector.c analyse_packet.c  -lpcap -lmemcached ./ac_automation.so
ac_automation: ac_automation.c
	g++ -shared -fPIC -o ac_automation.so ac_automation.c
clean:
	rm -rf *.o *.dSYM *.out *.dylib *.so
