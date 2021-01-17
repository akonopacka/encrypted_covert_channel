#include "../include/Receiver.h"


Receiver::Receiver() {
    Globals::message_ = "";
    Globals::last_seq_=1;
}

bool Receiver::timing_callback(const PDU &pdu) {
    Globals::time_received_ = std::chrono::high_resolution_clock::now();
    Globals::time_span_ = Globals::time_received_ - Globals::time_of_last_packet_;
    double interval = Globals::time_span_.count();
    const IP &ip = pdu.rfind_pdu<IP>();
    const UDP &udp = pdu.rfind_pdu<UDP>();
    Tins::Packet packet = Tins::Packet(pdu);
    Timestamp ts = packet.timestamp();
    double timestamp = ts.seconds() * 1000000 + ts.microseconds();
    std::cout << std::fixed << "Seconds: " << ts.seconds() << " microseconds:" << ts.microseconds() << endl;
    double inv = timestamp - Globals::last_packet_timestamp_;
    std::cout << "Inter: " << inv << " " << "Ts: " << timestamp << std::endl;
    if (udp.dport() == Globals::dst_port_) {
        if (inv < 1000) {
            Globals::message_ = Globals::message_ + "0";
            std::cout << "0" << endl<< endl;
        } else if (inv < 4000000) {
            Globals::message_ = Globals::message_ + "1";
            std::cout << "1" << endl<< endl;
        } else {
            if (Globals::message_ != "") {
                Globals::message_.erase(0, 1);
                std::cout << "Received message: " << Globals::message_ << endl;
                std::stringstream sstream(Globals::message_);
                std::string output;
                while (sstream.good()) {
                    std::bitset<8> bits;
                    sstream >> bits;
                    char c = char(bits.to_ulong());
                    output += c;
                }
                std::cout << "Encoded message: " << output << endl;
            }
            Globals::message_ = "";
        }
        Globals::time_of_last_packet_ = std::chrono::high_resolution_clock::now();
        Globals::last_packet_timestamp_ = timestamp;
    }
    return true;
}

bool Receiver::storage_callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    if (tcp.dport() == Globals::dst_port_) {
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.tot_len() << endl;
        int a = ip.tot_len() - 40;
        char c = static_cast<char>(a);
        if (c == '0') {
            std::cout << "Received message: " << Globals::message_ << endl;
            Globals::message_ = "";
        } else {
            Globals::message_ = Globals::message_ + c;
        }
    }
    return true;
}

bool Receiver::IP_id_callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    if (tcp.dport() == Globals::dst_port_) {
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.id() << endl;
        int a = ip.id();
        char c = static_cast<char>(a);
        if (c == '0') {
            std::cout << "Received message: " << Globals::message_ << endl;
            Globals::message_ = "";
        } else {
            Globals::message_ = Globals::message_ + c;
        }
    }
    return true;
}

template <typename Container>
bool in_quote(const Container& cont, const std::string& s)
{
    return std::search(cont.begin(), cont.end(), s.begin(), s.end()) != cont.end();
}

void Receiver::HTTP_callback(){

    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);


// Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

// Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( Globals::dst_port_ );

// Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    string message = "";
    bool end = false;
    while(!end){
        char buffer[1024] = {0};
        valread=read (new_socket , buffer, 1024);
        if ( valread== 0)
            continue;
        else{
            string str(buffer);
            memset(buffer, 0, 1024);
            if (str.find("fin.com")!=string::npos){
                std::stringstream sstream(message);
                std::string output;
                while (sstream.good()) {
                    std::bitset<8> bits;
                    sstream >> bits;
                    char c = char(bits.to_ulong());
                    output += c;
                }
                std::cout<<"Received message: "<<output<<std::endl;
                message = "";
                str = "";
                if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                         (socklen_t*)&addrlen))<0)
                {
                    perror("accept");
                    exit(EXIT_FAILURE);
                }
            }
            else{
                string s = "Host:";
                bool is_Host = in_quote( str, s );
                s = "host:";
                bool is_host = in_quote( str, s );
                if (is_Host){
                    message=message+'0';
                    str = "";
                }
                else if (is_host){
                    message=message+'1';
                    str = "";
                }
                char *hello = "Hello from server";
                send(new_socket , hello , strlen(hello) , 0 );
            }
            memset(buffer, 0, 1024);
        }
    }
}

bool Receiver::LSB_Hop_callback(const PDU &pdu) {
    const IPv6 &ip = pdu.rfind_pdu<IPv6>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
              << ip.dst_addr() << ':' << tcp.dport() << "    "
              << ip.hop_limit() << endl;
    int a = ip.hop_limit();
    if (a != 100){
        Globals::message_ = Globals::message_ + to_string(a & 1);
    }
    else{
        std::stringstream sstream(Globals::message_);
        std::string output;
        while (sstream.good()) {
            std::bitset<8> bits;
            sstream >> bits;
            char c = char(bits.to_ulong());
            output += c;
        }
        std::cout<<"Received message: "<<output<<std::endl;
        Globals::message_ = "";
    }
    return true;
}

bool Receiver::sequence_callback(const PDU &pdu){
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if (tcp.dport()==Globals::dst_port_){
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << tcp.seq() << endl;
        int seq = tcp.seq();
        if (seq == 0){
            Globals::message_.erase(0, 1);
            std::stringstream sstream(Globals::message_);
            std::string output;
            while (sstream.good()) {
                std::bitset<8> bits;
                sstream >> bits;
                char c = char(bits.to_ulong());
                output += c;
            }
            Globals::last_seq_=0;
            std::cout<<"Received message: "<<Globals::message_ << std::endl<< output<<std::endl;
            Globals::message_ = "";
        }
        else{
            if (seq == Globals::last_seq_ + 1){
                Globals::message_ = Globals::message_ + '0';
                Globals::last_seq_ = seq;
            }
            else{
                Globals::message_ = Globals::message_ + '1';
            }
        }
    }
    return true;
}

bool Receiver::loss_callback(const PDU &pdu){
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if (tcp.dport()==Globals::dst_port_){
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << tcp.seq() << endl;
        int seq = tcp.seq();
        if (seq == 0){
            std::cout<<"Bin: "<<Globals::message_<<std::endl;
            Globals::message_.pop_back();
            Globals::message_ = Globals::message_ + '1';
            std::stringstream sstream(Globals::message_);
            std::string output;

            while (sstream.good()) {
                std::bitset<8> bits;
                sstream >> bits;
                char c = char(bits.to_ulong());
                if (Globals::is_encrypted){

                }
                output += c;
            }
            Globals::last_seq_=1;
            std::cout<<"Received message: "<<Globals::message_ << std::endl<< output<<std::endl;
            if (Globals::is_encrypted){
                Cryptographer cryptographer = Cryptographer("aes");
                string decrypted_message = cryptographer.decrypt(output);
                std::cout<<"Decrypted: "<<decrypted_message <<std::endl;
            }

            Globals::message_ = "";
        }
        else{
            if (seq!=1){
                int i = seq - Globals::last_seq_;
                if (i==1){
                    Globals::message_ = Globals::message_ + '0';
                    Globals::last_seq_ = seq;
                }
                else{
                    std::string s(i-1, '1');
                    Globals::message_ = Globals::message_ + s+'0';
                    Globals::last_seq_ = Globals::last_seq_ + i;
                }
            }
        }
    }
    return true;
}

