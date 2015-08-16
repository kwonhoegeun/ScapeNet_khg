CC = gcc
CFLAGS = -Wall
LDFLAGS = -lm -lpcap -lpthread

all: scan

scan: senser_main.o senser_networkScan.o senser_nodeKill.o senser_portscan.o
	$(CC) -o $@ $^ $(LDFLAGS)

senser_main.o: senser_main.c senser_networkScan.h
	$(CC) $(CFLAGS) -c $<

senser_networkScan.o: senser_networkScan.c senser_networkScan.h
	$(CC) $(CFLAGS) -c $<

senser_nodeKill.o: senser_nodeKill.c senser_nodeKill.h
	$(CC) $(CFLAGS) -c $<

senser_portscan.o: senser_portscan.c senser_portscan.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o scan


