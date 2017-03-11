CC = gcc
CFLAGS = -W -Wall
LDFLAGS = -lm -lpcap -lpthread

scan: main.o network_scan.o node_kill.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c $<

network_scan.o: network_scan.c
	$(CC) $(CFLAGS) -c $<

node_kill.o: node_kill.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o scan


