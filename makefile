all: main.c memc_connector.c
	gcc -g -Wall -o main.o  main.c memc_connector.c -lpcap -lmemcached

clean:
	rm -rf *.o *.dSYM
