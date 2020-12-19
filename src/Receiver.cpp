#include "../include/Receiver.h"


Receiver::Receiver() {
    message_ = "";
}

bool Receiver::timing_callback(const PDU &pdu) {
    time_received_ = std::chrono::high_resolution_clock::now();
    time_span_ = time_received_ - time_of_last_packet_;
    double interval = time_span_.count();
    const IP &ip = pdu.rfind_pdu<IP>();
    const UDP &udp = pdu.rfind_pdu<UDP>();
    std::cout << udp.sport() << ' ';
    Tins::Packet packet = Tins::Packet(pdu);
    Timestamp ts = packet.timestamp();
    double timestamp = ts.seconds() * 1000000 + ts.microseconds();
    std::cout << std::fixed << "Seconds: " << ts.seconds() << " microseconds:" << ts.microseconds() << endl;
    double inv = timestamp - last_packet_timestamp_;
    std::cout << "Inter: " << inv << " " << "Ts: " << timestamp << std::endl;

    if (udp.dport() == 22) {
        if (inv < 1000) {
            message_ = message_ + "0";
            std::cout << "0" << endl;
        } else if (inv < 4000000) {
            message_ = message_ + "1";
            std::cout << "1" << endl;
        } else {
            if (message_ != "") {
                message_.erase(0, 1);
                std::cout << "Received message: " << message_ << endl;
                std::stringstream sstream(message_);
                std::string output;
                while (sstream.good()) {
                    std::bitset<8> bits;
                    sstream >> bits;
                    char c = char(bits.to_ulong());
                    output += c;
                }
                std::cout << "Uncoded message: " << output << endl;
            }
            message_ = "";
        }
//        std::cout<<"Received message: "<<message<<endl;
        time_of_last_packet_ = std::chrono::high_resolution_clock::now();
        last_packet_timestamp_ = ts.seconds() * 1000000 + ts.microseconds();
    }
    return true;
}

bool Receiver::storage_callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    if (tcp.dport() == 22) {
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.tot_len() << endl;
        int a = ip.tot_len() - 40;
        char c = static_cast<char>(a);

        if (c == '0') {
            std::cout << "Received message: " << message_ << endl;
            message_ = "";
        } else {
            message_ = message_ + c;
        }
    }
    return true;
}

bool Receiver::IP_id_callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    if (tcp.dport() == 22) {
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.tot_len() << endl;
        int a = ip.tot_len() - 40;
        char c = static_cast<char>(a);

        if (c == '0') {
            std::cout << "Received message: " << message_ << endl;
            message_ = "";
        } else {
            message_ = message_ + c;
        }
    }
    return true;
}
