all: main.c memc_connector.c
	gcc -g -Wall -o run.o  main.c memc_connector.c -lpcap -lmemcached

clean:
	rm -rf *.o *.dSYM
