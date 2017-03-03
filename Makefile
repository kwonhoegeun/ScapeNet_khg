CC = gcc
CFLAGS = -Wall
LDFLAGS = -lm -lpcap -lpthread

all: scan

scan: main.o network_scan.o node_kill.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.c network_scan.h
	$(CC) $(CFLAGS) -c $<

network_scan.o: network_scan.c network_scan.h
	$(CC) $(CFLAGS) -c $<

node_kill.o: node_kill.c node_kill.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o scan


