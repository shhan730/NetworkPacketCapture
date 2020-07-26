all: pcap

pcap: main.o
	g++ -o pcap main.cpp -lpcap

clean: 
	rm -f *.o
	rm -f pcap


