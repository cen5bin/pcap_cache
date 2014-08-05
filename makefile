all: main.c memc_connector.c analyse_packet.c ac_automation.c ac_automation
	llvm-gcc -g -Wall -o run.o  main.c memc_connector.c analyse_packet.c  -lpcap -lmemcached ./ac_automation.dylib
ac_automation: ac_automation.c
	llvm-g++ -dynamiclib -o ac_automation.dylib ac_automation.c
clean:
	rm -rf *.o *.dSYM *.out *.dylib *.so
