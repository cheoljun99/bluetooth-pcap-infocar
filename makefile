LDLIBS += -lpcap

all: bluetooth-pcap-infocar

pcap-test: bluetooth-pcap-infocar.c

clean:
	rm -f bluetooth-pcap-infocar *.o
