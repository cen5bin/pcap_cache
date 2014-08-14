edit: main.c analyse_packet
	gcc -o run.o main.c -lanalyse_packet -L. -lpcap -lmemcached
analyse_packet: memc_connector.c analyse_packet.c ac_automation
	gcc -c memc_connector.c
	gcc -c analyse_packet.c 
	ar rvl -o libanalyse_packet.a memc_connector.o analyse_packet.o ac_automation.o 
	rm *.o
ac_automation: ac_automation.cpp
	g++ -c -g ac_automation.cpp
clean:
	rm -rf *.o *.dSYM *.out *.dylib *.so *.a
