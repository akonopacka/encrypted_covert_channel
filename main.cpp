/*
	Raw TCP packets
*/
#include <stdio.h>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()
#include <iostream>
#include "TCP_Packet.h"

int main (void)
{
    TCP_Packet tcp_packet("192.168.1.18", "192.168.1.16", 1230, 1235);
    std::cout<<tcp_packet.send_packet();

    // sleep for 1 seconds
    sleep(1);
    std::cout<<"\n \nYou're the best!\n";
    return 0;
}

//Complete
