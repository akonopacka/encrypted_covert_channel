#ifndef ENCRYPTED_COVERT_CHANNEL_TCP_PACKET_H
#define ENCRYPTED_COVERT_CHANNEL_TCP_PACKET_H

#include <string>
#include <stdio.h>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()

class TCP_Packet
{
private:
    const char *src_address;
    const char *dst_address;
    uint16_t tcp_src_port;	/* source port */
    uint16_t tcp_dst_port;	/* destination port */
    char datagram[4096] , source_ip[32] , *data;

public:
    TCP_Packet(const char *srcAddress, const char *dstAddress, uint16_t tcpSrcPort, uint16_t tcpDstPort);

    std::string send_packet();
    unsigned short check_sum(unsigned short *ptr, int nbytes);
};
#endif //ENCRYPTED_COVERT_CHANNEL_TCP_PACKET_H
