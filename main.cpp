/*
	Raw TCP packets
*/
#include <stdio.h>    //for printf
#include <string.h> //memset
#include <sys/socket.h>    //for socket of course
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()
#include <iostream>
#include "TCP_Packet.h"
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    std::string dataStr = "";

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip *) (packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            data = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            // convert non-printable characters, other than carriage return, line feed,
            // or tab into periods when displayed.
            for (int i = 0; i < dataLength; i++) {
                if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                    dataStr += (char) data[i];
                } else {
                    dataStr += ".";
                }
            }

            // print the results
            std::cout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << std::endl;
        }
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--server")){
            std::cout << "Server!\n";

            int i;
            char *dev;
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* descr;
            const u_char *packet;
            struct pcap_pkthdr hdr;
            struct ether_header *eptr;    /* net/ethernet.h */
            struct bpf_program fp;        /* hold compiled program */
            bpf_u_int32 maskp;            /* subnet mask */
            bpf_u_int32 netp;             /* ip */

            if(argc != 2){
                fprintf(stdout, "Usage: %s \"expression\"\n", argv[0]);
                return 0;
            }

            /* Now get a device */
            dev = pcap_lookupdev(errbuf);

            if(dev == NULL) {
                fprintf(stderr, "%s\n", errbuf);
                exit(1);
            }
            /* Get the network address and mask */
            pcap_lookupnet(dev, &netp, &maskp, errbuf);

            /* open device for reading in promiscuous mode */
            descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
            if(descr == NULL) {
                printf("pcap_open_live(): %s\n", errbuf);
                exit(1);
            }

            /* loop for callback function */
            pcap_loop(descr, -1, my_callback, NULL);
        }
    }

    if (!strcmp(argv[1], "--client")) {
        std::cout << "Client\n";

        TCP_Packet tcp_packet("192.168.1.18", "192.168.1.16", 1239, 1235);
        // TODO zamienic send packet na zwracanie bool
        std::cout << tcp_packet.send_packet();

        // sleep for 1 seconds
        sleep(1);
        return 0;
    } else {
        std::cerr << "Bad usage";
        return 1;
    }

}

