//
// Created by root on 02/11/2020.
//

#include "../include/Sender.h"

Sender::Sender(const string &method, bool is_encrypted, string cipher_type) : method(method),
                                                                              is_encrypted(is_encrypted),
                                                                              cipher_type(cipher_type) {}
void send_thread(IP pkt){
    PacketSender sender;
    sender.send(pkt, Globals::interface_);
}
void send_thread_ipv6(IPv6 pkt){
    PacketSender sender;
    sender.send(pkt, Globals::interface_);
}

void Sender::send_with_timing_method(const string message_to_send) {
    std::cout << "Timing method" << endl;
    string word = message_to_send;
    string binaryString = "";
    string message = message_to_send;
    if (!is_encrypted) {
        for (char &_char: word) {
            binaryString += bitset<8>(_char).to_string();
        }
    } else {
        binaryString = message_to_send;
    }
    Globals::channel_message = binaryString;
    cout << "Bin: " << binaryString << endl;
    message = binaryString;
    PacketSender sender_(Globals::interface_);
    EthernetII packet_;
    packet_ /= IP(Globals::IPv4_address) / UDP(Globals::dst_port_, Globals::src_port_) ;

    try{
        sender_.send(packet_);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
    }
    int interval = Globals::time_interval_1_ms_*1.5;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        PacketSender sender(Globals::interface_);
        EthernetII packet;
        packet /= IP(Globals::IPv4_address) / UDP(Globals::dst_port_, Globals::src_port_) ;
        if (message[i] == '0') {
            std::cout << i << ". " << message[i] << endl;
            try{
                sender.send(packet);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
        } else {
            std::cout << i << ". " << message[i] << endl;
            try{
                sender.send(packet);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
    }
    try{
        sender_.send(packet_);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender_.send(packet_);
    }
    std::cout << endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    try{
        sender_.send(packet_);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender_.send(packet_);
    }
    std::cout << "Sending completed.";
}

void Sender::send_with_storage_method(const string message_to_send) {
    std::cout << "Storage method" << endl;
//    std::cout << "Sending message:" << message_to_send << endl;
    string message = message_to_send;

    int count = 0;
    long sum = 0;
//    Initiate message vector
    vector<int> message_vector;
    if(is_encrypted){
        int counter = ceil((float) message.length() / 8);
        string ciphertext_complete;
        for (int i = 0; i < counter; i++) {
            string bin_string = message.substr(i * 8, 8);
            int number = stoi(bin_string, 0, 2);
            message_vector.push_back(number);
            std::bitset<8> bits;
            std::stringstream sstream(bin_string);
            sstream >> bits;
            unsigned char c = (unsigned char) (bits.to_ulong());
            Globals::channel_message += c;
        }
    }
    else{
        Globals::channel_message = message_to_send;
        for (char c : message) {
            int char_number = (int) c;
            message_vector.push_back(char_number);
        }
    }

    cout<<"Message_vector size: "<<message_vector.size()<<endl;
//  Sending the message
    PacketSender sender_(Globals::interface_);
    std::string s_data(400, 'a');
    TCP tcp_first = TCP(Globals::dst_port_, Globals::src_port_);
    tcp_first.flags(Tins::TCP::RST);
    IP pkt_ = IP(Globals::IPv4_address) / tcp_first/ RawPDU(s_data);
    try{
        sender_.send(pkt_);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender_.send(pkt_);
    }

    int counter = 0;
//    int sum_values=0;

    PacketSender sender(Globals::interface_,0,0);
    for (int x : message_vector){
        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
        tcp.flags(TCP::RST);
        std::string s(x, 'a');
//        IP pkt = IP(Globals::IPv4_address) / tcp / RawPDU(s);
        EthernetII packet;
        packet /= IP(Globals::IPv4_address, "10.10.1.5") / tcp / RawPDU(s) ;
        bool continue_sending = false;
        while(!continue_sending){
            try{
                auto start_sending_packet = high_resolution_clock::now();
                sender.send(packet);
                auto stop_sending_packet = high_resolution_clock::now();
                auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
                cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
                sum = sum + sending_duration_packet_nano.count();
                continue_sending = true;
            }
            catch (Tins::socket_write_error e){
                cout<<"Sending error : " <<e.what()<<"!"<<endl;
//                if(e.what()!="No buffer space available"){
//                    cout<<"Continue sending"<<endl;
//                    continue_sending = true;
//                }
                usleep(50);
            }
        }
        usleep(50);
        counter ++;
    }

    PacketSender sender_end_packet(Globals::interface_,0,0);
    int end_number = 500;
    std::string s(end_number, 'a');
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.flags(Tins::TCP::RST);
    IP packet_end = IP(Globals::IPv4_address) / tcp/ RawPDU(s);
    bool continue_sending = false;
    while(!continue_sending){
        try{
            auto start_sending_packet = high_resolution_clock::now();
            sender_end_packet.send(packet_end);
            auto stop_sending_packet = high_resolution_clock::now();
            auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
            cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
            sum = sum + sending_duration_packet_nano.count();
            continue_sending = true;
            usleep(50);
            cout<<"Send last packet"<<endl;
        }
        catch (Tins::socket_write_error e){
            cout<<"Sending error :" <<e.what()<<endl;
            usleep(50);
        }
    }
    cout<<"Number of sent packets: "<<counter<<endl;
    cout<<"avg packet send duraation: "<<sum/counter<<endl;
//    cout<<"avg packet value: "<<sum_values/counter<<endl;


}

void Sender::send_with_storage_method_IP_id(const string message_to_send) {
    std::cout << "Storage IP_id method" << endl;
    string binaryString = "";
    string message = message_to_send;

    int count = 0;
    long sum = 0;
//    Initiate message vector
    vector<int> message_vector;
    if(is_encrypted){
        int counter = ceil((float) message.length() / 8);
        for (int i = 0; i < counter; i++) {
            string bin_string = message.substr(i * 8, 8);
            int number = stoi(bin_string, 0, 2);
            message_vector.push_back(number);
            std::bitset<8> bits;
            std::stringstream sstream(bin_string);
            sstream >> bits;
            unsigned char c = (unsigned char) (bits.to_ulong());
            Globals::channel_message += c;
        }
    }
    else{
        Globals::channel_message = message_to_send;
        for (char c : message) {
            message_vector.push_back((int)c);
        }
    }

//    Sending
    PacketSender sender(Globals::interface_,0,0);
    for (int x : message_vector) {
        IP ip = IP(Globals::IPv4_address, "10.10.1.5");
        ip.id(x);
        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
        tcp.flags(Tins::TCP::RST);
        EthernetII packet;
        packet /= ip / tcp ;

        bool continue_sending = false;
        while(!continue_sending){
            try{
                auto start_sending_packet = high_resolution_clock::now();
                sender.send(packet);
                auto stop_sending_packet = high_resolution_clock::now();
                auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
                cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
                sum = sum + sending_duration_packet_nano.count();
                continue_sending = true;
            }
            catch (Tins::socket_write_error e){
                cout<<"Sending error :" <<e.what()<<endl;
                if(e.what()!="No buffer space available"){
                    continue_sending = true;
                }
                usleep(50);
            }
        }
        count ++;
        usleep(50);
    }

    IP ip = IP(Globals::IPv4_address);
    ip.id(1000);
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.flags(Tins::TCP::RST);
    IP pkt = ip / tcp / RawPDU("");
    bool continue_sending = false;
    while(!continue_sending){
        try{
            auto start_sending_packet = high_resolution_clock::now();
            sender.send(pkt);
            auto stop_sending_packet = high_resolution_clock::now();
            auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
            cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
            sum = sum + sending_duration_packet_nano.count();
            continue_sending = true;
        }
        catch (Tins::socket_write_error e){
            cout<<"Sending error :" <<e.what()<<endl;
            if(e.what()!="No buffer space available"){
                continue_sending = true;
            }
            usleep(50);
        }
    }

    cout<<"Number of sent packets: "<<count<<endl;
    cout<<"avg packet send duraation: "<<sum/count<<endl;

}

void Sender::send_with_HTTP_case_method(const string message_to_send) {
    std::cout << "Storage HTTP case method" << endl;
    string word = message_to_send;
    string binaryString = "";
    if (!is_encrypted) {
        for (char &_char: word) {
            binaryString += bitset<8>(_char).to_string();
        }
    } else {
        binaryString = message_to_send;
    }

    Globals::channel_message = binaryString;
    string message = binaryString;
    cout << "Message to send: " << message << endl;

    int sock = 0, valread;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(Globals::dst_port_);

//     Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, Globals::IPv4_address.c_str(), &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
    }

    if (connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
    }
    stringstream ss;
    int sum = 0;
    int counter =0;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        string input;
        if (message[i] == '0') {
            input = "Host: google.com\r\n";
        }
        else{
            input = "host: google.com\r\n";
        }
        ss << "GET / HTTP/1.1\r\n"
           << input
           << "Accept: application/json\r\n"
           << "\r\n\r\n";
        string request = ss.str();
        auto start_sending_packet = high_resolution_clock::now();
//        send(sock, request.c_str(), request.length(), 0);
        sendto(sock, request.c_str(), request.length(), 0, NULL, 0);
        auto stop_sending_packet = high_resolution_clock::now();
        auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
        cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
        sum = sum + sending_duration_packet_nano.count();

        ss.str("");
        char buffer[1024] = {0};
        valread = read(sock, buffer, 1024);
        usleep(50);
        counter++;
    }
    ss << "GET /  HTTP/1.1\r\n"
       << "Host: fin.com\r\n"
       << "Accept: application/json\r\n"
       << "\r\n\r\n";
    string request = ss.str();
    send(sock, request.c_str(), request.length(), 0);
    ss.str("");
    cout<<"Number of sent packets: "<<counter<<endl;
    cout<<"avg packet send duration: "<<sum/counter<<endl;
    std::cout << "Finished sending" << endl;
}

void Sender::send_with_LSB_Hop_method(const string message_to_send) {
    std::cout << "Storage LSB Hop Limit method" << endl;
    string word = message_to_send;
    string binaryString = "";
    if (!is_encrypted) {
        for (char &_char: word) {
            binaryString += bitset<8>(_char).to_string();
        }
    } else {
        binaryString = message_to_send;
    }
    Globals::channel_message = binaryString;
    string message = binaryString;

    int sum = 0;
    int counter =0;
    PacketSender sender(Globals::interface_,0,0);
    for (char i : message) {
        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
        tcp.flags(Tins::TCP::RST);
        EthernetII packet;
        IPv6 iPv6 = IPv6(Globals::IPv6_address);
        if (i == '0') {
            iPv6.hop_limit(254);
            packet /= iPv6 / tcp ;

            bool continue_sending = false;
            while(!continue_sending){
                try{
                    auto start_sending_packet = high_resolution_clock::now();
                    sender.send(packet);
                    auto stop_sending_packet = high_resolution_clock::now();
                    auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
                    cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
                    sum = sum + sending_duration_packet_nano.count();
                    continue_sending = true;
                }
                catch (Tins::socket_write_error e){
                    cout<<"Sending error :" <<e.what()<<endl;
                    if(e.what()!="No buffer space available"){
                        continue_sending = true;
                    }
                    usleep(50);
                }
            }

//            std::cout << message[i] << endl;
        } else {
            iPv6.hop_limit(255);
            packet /= iPv6 / tcp;
            bool continue_sending = false;
            while(!continue_sending){
                try{
                    auto start_sending_packet = high_resolution_clock::now();
                    sender.send(packet);
                    auto stop_sending_packet = high_resolution_clock::now();
                    auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
                    cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
                    sum = sum + sending_duration_packet_nano.count();
                    continue_sending = true;
                }
                catch (Tins::socket_write_error e){
                    cout<<"Sending error :" <<e.what()<<endl;
                    if(e.what()!="No buffer space available"){
                        continue_sending = true;
                    }
                    usleep(50);
                }
            }
//            std::cout << message[i] << endl;
        }
        counter++;
        usleep(50);
    }
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.flags(Tins::TCP::RST);
    EthernetII packet;
    IPv6 iPv6 = IPv6(Globals::IPv6_address);
    iPv6.hop_limit(100);
    packet /= iPv6 / tcp;

    bool continue_sending = false;
    while(!continue_sending){
        try{
            auto start_sending_packet = high_resolution_clock::now();
            sender.send(packet);
            auto stop_sending_packet = high_resolution_clock::now();
            auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
            cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
            sum = sum + sending_duration_packet_nano.count();
            continue_sending = true;
        }
        catch (Tins::socket_write_error e){
            cout<<"Sending error :" <<e.what()<<endl;
            if(e.what()!="No buffer space available"){
                continue_sending = true;
            }
            usleep(50);
        }
    }
    cout<<"Number of sent packets: "<<counter<<endl;
    cout<<"avg packet send duration: "<<sum/counter<<endl;
    std::cout << "Finished sending" << endl;
}

void Sender::send_with_sequence_method(const string message_to_send) {
    std::cout << "Sequence TCP method" << endl;
    string word = message_to_send;
    string binaryString = "";
    if (!is_encrypted) {
        for (char &_char: word) {
            binaryString += bitset<8>(_char).to_string();
        }
    } else {
        binaryString = message_to_send;
    }
    Globals::channel_message = binaryString;
//    cout << "Message to send: " << word << endl << "Bin: " << binaryString << endl;
    string message = binaryString;
    int seq = 1;

    PacketSender sender_(Globals::interface_,0,0);
    TCP tcp_ = TCP(Globals::dst_port_, Globals::src_port_);
    tcp_.seq(1);
    tcp_.flags(Tins::TCP::RST);
    EthernetII packet_;
    packet_ /= IP(Globals::IPv4_address, "10.10.1.5") / tcp_ ;
    sender_.send(packet_);

    PacketSender sender(Globals::interface_,0,0);

    int counter = 0;
    int sum = 0;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
            seq = seq + 1;
            tcp.seq(seq);
            tcp.flags(Tins::TCP::RST);
            EthernetII packet;
            packet /= IP(Globals::IPv4_address, "10.10.1.5")  / tcp ;
            bool continue_sending = false;
            while(!continue_sending){
                try{
                    auto start_sending_packet = high_resolution_clock::now();
                    sender.send(packet);
                    auto stop_sending_packet = high_resolution_clock::now();
                    auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
                    cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
                    sum = sum + sending_duration_packet_nano.count();
                    continue_sending = true;
                }
                catch (Tins::socket_write_error e){
                    cout<<"Sending error :" <<e.what()<<endl;
                    if(e.what()!="No buffer space available"){
                        continue_sending = true;
                    }
                    usleep(50);
                }
            }

        } else {
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
            tcp.seq(seq);
            tcp.flags(Tins::TCP::RST);
            EthernetII packet;
            packet /= IP(Globals::IPv4_address, "10.10.1.5")  / tcp ;
            bool continue_sending = false;
            while(!continue_sending){
                try{
                    auto start_sending_packet = high_resolution_clock::now();
                    sender.send(packet);
                    auto stop_sending_packet = high_resolution_clock::now();
                    auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
                    cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
                    sum = sum + sending_duration_packet_nano.count();
                    continue_sending = true;
                    usleep(50);
                }
                catch (Tins::socket_write_error e){
                    cout<<"Sending error :" <<e.what()<<endl;
                    if(e.what()!="No buffer space available"){
                        continue_sending = true;
                    }
                    usleep(50);
                }
            }
        }
        counter++;
        usleep(50);
    }
    cout<<"Number of sent packets: "<<counter<<endl;
    cout<<"avg packet send duration: "<<sum/counter<<endl;

//    tcp_.seq(seq);
//    tcp_.flags(Tins::TCP::RST);
//    packet_ /= IP(Globals::IPv4_address, "10.10.1.5") / tcp_ ;
//
//
//    while(!continue_sending){
//        try{
//            sender_.send(packet_);
//            continue_sending = true;
//            usleep(50);
//        }
//        catch (Tins::socket_write_error e){
//            cout<<"Sending error :" <<e.what()<<endl;
//            usleep(50);
//        }
//    }

    PacketSender sender_2(Globals::interface_,0,0);
    EthernetII packet_2;
    TCP tcp_2 = TCP(Globals::dst_port_, Globals::src_port_);
    tcp_2.seq(0);
    packet_2 /= IP(Globals::IPv4_address) / tcp_2 ;

    bool continue_sending = false;
    while(!continue_sending){
        try{
            sender_2.send(packet_2);
            continue_sending = true;
            usleep(50);
        }
        catch (Tins::socket_write_error e){
            cout<<"Sending error :" <<e.what()<<endl;
            usleep(50);
        }
    }
}

void Sender::send_with_loss_method(const string message_to_send) {
    std::cout << "Loss method" << endl;
    string word = message_to_send;
    string binaryString = "";
    if (!is_encrypted) {
        for (char &_char: word) {
            binaryString += bitset<8>(_char).to_string();
        }
    } else {
        binaryString = message_to_send;
    }
    Globals::channel_message = binaryString;
    string message = binaryString;
    int seq = 1;
    PacketSender sender_(Globals::interface_,0,0);
    TCP tcp_ = TCP(Globals::dst_port_, Globals::src_port_);
    tcp_.seq(seq);
    tcp_.flags(Tins::TCP::RST);
    EthernetII packet_;
    packet_ /= IP(Globals::IPv4_address, "10.10.1.5") / tcp_ ;
    try {
        sender_.send(packet_);
    }catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender_.send(packet_);
    }

    seq = seq + 1;
    int counter = 0;
    int sum = 0;
    PacketSender sender(Globals::interface_,0,0);
    for (char i : message) {
        if (i == '0') {
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
            tcp.seq(seq);
            tcp.flags(Tins::TCP::RST);
            EthernetII packet;
            packet /= IP(Globals::IPv4_address, "10.10.1.5") / tcp ;
            bool continue_sending = false;
            while(!continue_sending){
                try{
                    auto start_sending_packet = high_resolution_clock::now();
                    sender.send(packet);
                    auto stop_sending_packet = high_resolution_clock::now();
                    auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
                    cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
                    sum = sum + sending_duration_packet_nano.count();
                    continue_sending = true;
                }
                catch (Tins::socket_write_error e){
                    cout<<"Sending error :" <<e.what()<<endl;
                    if(e.what()!="No buffer space available"){
                        continue_sending = true;
                    }
                    usleep(50);
                }
            }
        }
        seq = seq + 1;
        counter++;
        usleep(50);
    }

    tcp_.seq(seq);
    tcp_.flags(Tins::TCP::RST);
    EthernetII packet;
    packet /= IP(Globals::IPv4_address, "10.10.1.5") / tcp_ ;
    bool continue_sending = false;
    while(!continue_sending){
        try{
            auto start_sending_packet = high_resolution_clock::now();
            sender.send(packet);
            auto stop_sending_packet = high_resolution_clock::now();
            auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
            cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
            sum = sum + sending_duration_packet_nano.count();
            continue_sending = true;
        }
        catch (Tins::socket_write_error e){
            cout<<"Sending error :" <<e.what()<<endl;
            if(e.what()!="No buffer space available"){
                continue_sending = true;
            }
            usleep(50);
        }
    }

    EthernetII packet_2;
    tcp_.seq(0);
    tcp_.flags(Tins::TCP::RST);
    packet_2 /= IP(Globals::IPv4_address, "10.10.1.5") / tcp_ ;

    continue_sending = false;
    while(!continue_sending){
        try{
            auto start_sending_packet = high_resolution_clock::now();
            sender_.send(packet_2);
            auto stop_sending_packet = high_resolution_clock::now();
            auto sending_duration_packet_nano = duration_cast<nanoseconds>(stop_sending_packet - start_sending_packet);
            cout<<"Sending packets time: "<< sending_duration_packet_nano.count() <<" ns"  <<  endl;
            sum = sum + sending_duration_packet_nano.count();
            continue_sending = true;
        }
        catch (Tins::socket_write_error e){
            cout<<"Sending error :" <<e.what()<<endl;
            if(e.what()!="No buffer space available"){
                continue_sending = true;
            }
            usleep(50);
        }
    }
    cout<<"Number of sent packets: "<<counter<<endl;
    cout<<"avg packet send duration: "<<sum/counter<<endl;
    std::cout << "Sending finished" << endl;
}

void Sender::send_message(string message_to_send) {
    std::cout << "Sending method: " << method << ", Message is encrypted: " << std::boolalpha << is_encrypted << endl;
    string m = method;
    std::string duration_of_encryption_with_key_loading = "----";
    if (is_encrypted) {
        message_to_send += char(0);
        Cryptographer cryptographer = Cryptographer(cipher_type);
        // Get starting timepoint
        auto start = high_resolution_clock::now();
        message_to_send = cryptographer.encrypt(message_to_send);
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        duration_of_encryption_with_key_loading = std::to_string(duration.count());
        std::cout << "Encrypted message: " << message_to_send << endl;
        string decrypted = cryptographer.decrypt(message_to_send);
        std::cout << "Decrypt check: " << decrypted << endl;
    }
    usleep(2500000);

    // Get starting timepoint
    auto start_sending = high_resolution_clock::now();
    if (method == "storage") {
        send_with_storage_method(message_to_send);
    } else if (method == "IP_id") {
        send_with_storage_method_IP_id(message_to_send);
    } else if (method == "HTTP") {
        send_with_HTTP_case_method(message_to_send);
    } else if (method == "LSB") {
        send_with_LSB_Hop_method(message_to_send);
    } else if (method == "sequence") {
        send_with_sequence_method(message_to_send);
    } else if (method == "loss") {
        send_with_loss_method(message_to_send);
    } else if (method == "timing") {
        send_with_timing_method(message_to_send);
    }
    auto stop_sending = high_resolution_clock::now();
    auto sending_duration = duration_cast<microseconds>(stop_sending - start_sending);
    std::string time_of_sending;
    time_of_sending = std::to_string(sending_duration.count());
    string channel_message = Globals::channel_message;
    float message_entropy = Evaluation::calculate_entropy(Globals::channel_message);

    //            Saving to general file
    std::string combined_results_path = Globals::results_path;
    combined_results_path += "_client_" + Globals::covert_channel_type_ + "_" + Globals::cipher_type_ + ".csv";

    //              Write the column names to result file
    std::ifstream infile(combined_results_path);
    bool file_exists = infile.good();
    if (!file_exists){
        std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
        infile_stream << "message_entropy;duration_of_encryption_with_key_loading[ns];time_of_sending[ns]\n";
    }

    std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
    std:string results = std::to_string(message_entropy) + ";" + duration_of_encryption_with_key_loading + ";"
                         + time_of_sending + "\n";
    log << results;
    std::cout << "General results saved to : " << combined_results_path << std::endl;
    std::cout<< "message_entropy;duration_of_encryption_with_key_loading[ns];time_of_sending[ns]"<<endl;
    std::cout << results << std::endl;
    log.close();
}

