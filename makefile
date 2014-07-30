all: main.c memc_connector.c analyse_packet.c
	gcc -g -Wall -o run.o  main.c memc_connector.c analyse_packet.c -lpcap -lmemcached

clean:
	rm -rf *.o *.dSYM
