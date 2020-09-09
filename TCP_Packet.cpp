#include "TCP_Packet.h"

std::string TCP_Packet::send_packet() {
    //Create a raw socket
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if (s == -1) {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    } else {
        printf("Socket created\n");
    }

    //zero out the packet buffer
    memset(datagram, 0, 4096);

    //IP header
    struct iphdr *ip_header = (struct iphdr *) datagram;

    //TCP header
    struct tcphdr *tcp_header = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct sockaddr_in sin;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, "Martin  is so so so cute");

    //some address resolution
    strcpy(source_ip, src_address);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(666);
    sin.sin_addr.s_addr = inet_addr(dst_address);

    //Fill in the IP Header
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    ip_header->id = htonl(54321);    //Id of this packet
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;        //Set to 0 before calculating checksum
    ip_header->saddr = inet_addr(source_ip);    //Spoof the source ip address
    ip_header->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    ip_header->check = check_sum((unsigned short *) datagram, ip_header->tot_len);

    //TCP Header
    tcp_header->source = htons(tcp_src_port);
    tcp_header->dest = htons(tcp_dst_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;    //tcp header size
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840);    /* maximum allowed window size */
    tcp_header->check = 0;    //leave checksum 0 now, filled later by pseudo header
    tcp_header->urg_ptr = 0;


    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }
    //Send the packet
    if (sendto(s, datagram, ip_header->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("sendto failed");
        return "sendto failed";
    }
        //Data send successfully
    else {
        return "Packet sent";
    }

}

/*
	Generic checksum calculation function
*/
unsigned short TCP_Packet::check_sum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) ~sum;

    return (answer);
}

TCP_Packet::TCP_Packet(const char *srcAddress, const char *dstAddress, uint16_t tcpSrcPort, uint16_t tcpDstPort)
        : src_address(srcAddress), dst_address(dstAddress), tcp_src_port(tcpSrcPort), tcp_dst_port(tcpDstPort) {}
