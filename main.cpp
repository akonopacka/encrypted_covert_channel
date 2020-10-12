/*
	Better description
*/
#include <string.h> //memset
#include <unistd.h> // sleep()
#include <iostream>
#include <tins/tins.h>
#include <ctime>
#include <chrono>
#include <unistd.h>
#include <thread>

using namespace Tins;
using namespace std;

string message = "";
std::time_t start = std::time(nullptr);
std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
std::chrono::high_resolution_clock::time_point time_of_last_packet = std::chrono::high_resolution_clock::now();

bool callback_storage_CC(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if(ip.dst_addr()=="192.55.0.1"){
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.tot_len() << endl;
        int a = ip.tot_len()-40;
        char c = static_cast<char>(a);

        message = message+c;
    }
    if (message[message.size()-1] == '0'){
        std::cout<<"Received message: "<<message<<endl;
        message = "";
    }
    return true;
}

bool callback_timing_CC(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if(ip.dst_addr()=="192.55.0.1"){
        std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> time_span = t2 - time_of_last_packet;
        std::cout << "It took me " << time_span.count() << " milliseconds."<<std::endl;
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.tot_len() << endl;
        int a = ip.tot_len()-40;
        char c = static_cast<char>(a);

        message = message+c;
        time_of_last_packet = std::chrono::high_resolution_clock::now();
    }
    if (message[message.size()-1] == '0'){
        std::cout<<"Received message: "<<message<<endl;
        message = "";
    }

    return true;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {
            std::cout << "Server!\n";

            Sniffer("wlo1").sniff_loop(callback_timing_CC);
        }
    }

    if (!strcmp(argv[1], "--client")) {
        std::cout << "Client\n";
        string message = "HELLO1";
        for (std::string::size_type i = 0; i < message.size(); i++) {

            char a = message[i];
            int ia = (int)a;
            std::cout << message[i] << ' '<<ia<<endl;
            PacketSender sender;
            std::string s(ia, 'a');
            IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU(s);
            sender.send(pkt);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::cout<<endl;

        PacketSender sender;
        int ia = (int)'0';
        std::string s(ia, 'a');
        IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU(s);
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
