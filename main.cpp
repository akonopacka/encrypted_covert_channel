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

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--server"))
            std::cout << "Server!\n";

        if (!strcmp(argv[1], "--client")) {
            std::cout << "Client\n";

            TCP_Packet tcp_packet("192.168.1.18", "192.168.1.16", 1230, 1235);
            // TODO zamienic send packet na zwracanie bool
            std::cout << tcp_packet.send_packet();

            // sleep for 1 seconds
            sleep(1);
            return 0;
        }
    } else {
        std::cerr << "Bad usage";
        return 1;
    }

}

