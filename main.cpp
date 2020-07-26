#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

    /* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* dont fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)		(((ip)->ip_vhl) >> 4)

    /* TCP header */
    typedef u_int tcp_seq;

    struct sniff_tcp {
        u_short th_sport;	/* source port */
        u_short th_dport;	/* destination port */
        tcp_seq th_seq;		/* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
        u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
    };

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const unsigned char *payload; /* Packet payload */
    u_int size_ip;
    u_int size_tcp;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        //Packet INFO
        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return 1;
        }
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return 1;
        }
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

            //Print Eithernet INFO
            char* eth_d = (char*)ethernet->ether_dhost;
            char* eth_s = (char*)ethernet->ether_shost;
            printf("Eitherner Header INFO(src mac -> dst mac):\n");
            printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n", eth_s[0], eth_s[2], eth_s[4], eth_s[6], eth_s[8], eth_s[10], eth_d[0], eth_d[2], eth_d[4], eth_d[6], eth_d[8], eth_d[10]);

            //Print IP INFO
            char ip_d[1024]; //= inet_ntoa(ip->ip_dst);
            char ip_s[1024]; //= inet_ntoa(ip->ip_src);
            strcpy(ip_d, inet_ntoa(ip->ip_dst));
            strcpy(ip_s, inet_ntoa(ip->ip_src));
            printf("IP Header INFO(src ip -> dst ip):\n");
            printf("%s -> %s\n", ip_s, ip_d);

            //Print TCP INFO
            printf("TCP Header INFO(src port -> dst port):\n");
            printf("%d->%d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));

            // Print Payload INFO
            printf("Payload INFO(MAX 16 Byte)(If there is no Payload this prints nothing):\n");
            int data_size = header->caplen - size_ip - size_tcp - SIZE_ETHERNET;
            if(data_size > 16) data_size = 16;
            if(data_size != 0){
                for(int i=0; i< data_size; i++){
                    //if(payload[i] == '\0' || payload == NULL) break;
                    printf("%02x ", payload[i]);
                }
                printf("\n");
            }
        printf("\n\n");
    }

    pcap_close(handle);
}
