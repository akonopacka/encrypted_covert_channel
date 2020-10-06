/*
	Better description
*/
#include <string.h> //memset
#include <sys/socket.h>    //for socket of course
#include <stdlib.h> //for exit(0);
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

bool callback(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
              << ip.dst_addr() << ':' << tcp.dport() << endl;
    return true;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {
            std::cout << "Server!\n";

            Sniffer("wlo1").sniff_loop(callback);
        }
    }

    if (!strcmp(argv[1], "--client")) {
        std::cout << "Client\n";

        PacketSender sender;
        IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU("Martin is still cute");
        sender.send(pkt);
        std::cout << "Packet has been sent";

        // sleep for 1 seconds
        sleep(1);
        return 0;
    } else {
        std::cerr << "Bad usage";
        return 1;
    }

}

