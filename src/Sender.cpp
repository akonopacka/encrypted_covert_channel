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
    PacketSender sender;
    IP pkt = IP(Globals::IPv4_address) / UDP(Globals::dst_port_, Globals::src_port_);
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
    }
    int interval = Globals::time_interval_1_ms_*1.5;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            std::cout << i << ". " << message[i] << endl;
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
        } else {
            std::cout << i << ". " << message[i] << endl;
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
    }
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send(pkt);
    }
    std::cout << endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send(pkt);
    }
    std::cout << "Sending completed.";
}

void Sender::send_with_storage_method(const string message_to_send) {
    std::cout << "Storage method" << endl;
//    std::cout << "Sending message:" << message_to_send << endl;
    string message = message_to_send;
    PacketSender sender(Globals::interface_,0,0);
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
            Globals::channel_message += std::to_string(number);
        }
    }
    else{
        Globals::channel_message = message_to_send;
        for (char c : message) {
            int char_number = (int) c;
            message_vector.push_back(char_number);
        }
    }
//  Sending the message
    auto start_sending = high_resolution_clock::now();
    std::string s_data(400, 'a');
    TCP tcp_first = TCP(Globals::dst_port_, Globals::src_port_);
    tcp_first.flags(Tins::TCP::RST);
    IP pkt_ = IP(Globals::IPv4_address) / tcp_first/ RawPDU(s_data);
    try{
        sender.send_recv(pkt_);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send(pkt_);
    }
    for (int x : message_vector){
        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
        tcp.flags(Tins::TCP::RST);
        std::string s(x, 'a');
        IP pkt = IP(Globals::IPv4_address) / tcp / RawPDU(s);
        try{
            sender.send_recv(pkt);
        }
        catch (Tins::socket_write_error){
            cout<<"Sending error \n";
        }
    }
    int end_number = 500;
    std::string s(end_number, 'a');
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.flags(Tins::TCP::RST);
    IP pkt = IP(Globals::IPv4_address) / tcp/ RawPDU(s);
    try{
        sender.send_recv(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send_recv(pkt);
    }
    auto stop_sending = high_resolution_clock::now();
    auto sending_duration = duration_cast<microseconds>(stop_sending - start_sending);
    cout<<"Sending packets time: "<< sending_duration.count() << endl;

//    if (is_encrypted) {
//        message = message_to_send;
//        int block_size = 8;
//        int counter = ceil((float) message.length() / block_size);
//        string ciphertext_complete;
//        for (int i = 0; i < counter; i++) {
//            auto start_send= high_resolution_clock::now();
//            string bin_string = message.substr(i * block_size, block_size);
//            int number = stoi(bin_string, 0, 2);
//            std::string s(number, 'a');
//            Globals::channel_message += std::to_string(number);
//            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::URG);
//            tcp.flags(Tins::TCP::RST);
//            IP pkt = IP(Globals::IPv4_address) / tcp / RawPDU(s);
//            auto stop_send = high_resolution_clock::now();
//            try{
//                sender.send(pkt);
//            }
//            catch (Tins::socket_write_error){
//                cout<<"Sending error \n";
//            }
//
//            auto send_duration = duration_cast<microseconds>(stop_send - start_send);
//            sum =sum + send_duration.count();
//            count++;
////            cout<<"Send : "<< number << " " <<  bin_string << endl;
//            cout<< "Time for one packet: "<< send_duration.count() <<endl;
//        }
//        cout<<"avg time of sending one packet: "<< sum/count<<endl;
//        int ia = 500;
//        std::string s(ia, 'a');
//        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//        tcp.flags(Tins::TCP::URG);
//        tcp.flags(Tins::TCP::RST);
//        IP pkt = IP(Globals::IPv4_address) / tcp/ RawPDU(s);
//        try{
//            sender.send(pkt);
//        }
//        catch (Tins::socket_write_error){
//            cout<<"Sending error \n";
//            sender.send(pkt);
//        }
//    } else {
//        Globals::channel_message = message_to_send;
//        message = message_to_send;
//        for (char a : message) {
//            auto start_send= high_resolution_clock::now();
//            int ia = (int) a;
//            std::string s(ia, 'a');
//            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::URG);
//            tcp.flags(Tins::TCP::RST);
//            IP pkt = IP(Globals::IPv4_address) / tcp / RawPDU(s);
//            auto stop_send = high_resolution_clock::now();
//            try{
//                sender.send(pkt);
//            }
//            catch (Tins::socket_write_error){
//                cout<<"Sending error \n";
//            }
//
//            auto send_duration = duration_cast<microseconds>(stop_send - start_send);
//            sum =sum + send_duration.count();
//            count++;
////            cout<<"Send : "<< number << " " <<  bin_string << endl;
//            cout<< "Time for one packet: "<< send_duration.count() <<endl;
//        }
//        cout<<"avg time of sending one packet: "<< sum/count<<endl;
//        int ia = 500;
//        std::string s(ia, 'a');
//        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//        tcp.flags(Tins::TCP::URG);
//        tcp.flags(Tins::TCP::RST);
//        IP pkt = IP(Globals::IPv4_address) / tcp / RawPDU(s);
//        try{
//            sender.send(pkt);
//        }
//        catch (Tins::socket_write_error){
//            cout<<"Sending error \n";
//            sender.send(pkt);
//        }
//    }
}

void Sender::send_with_storage_method_IP_id(const string message_to_send) {
    std::cout << "Storage IP_id method" << endl;
    string binaryString = "";
    string message = message_to_send;
    PacketSender sender;
    sender.default_interface(Globals::interface_);
    if (!is_encrypted) {
        Globals::channel_message = message_to_send;
//        cout << "Message to send: " << message << endl;
        IP ip = IP(Globals::IPv4_address);
        cout<<"Message counter "<<message.size()<<endl;
        for (std::string::size_type i = 0; i < message.size(); i++) {
            char a = message[i];
            ip.id((int) a);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::PSH);
            IP pkt = ip / tcp / RawPDU("");
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
//            std::cout << message[i] << ' ' << ia << endl;
        }
        int ia = 1000;
        ip.id(ia);
        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//        tcp.flags(Tins::TCP::PSH);
        IP pkt = ip / tcp / RawPDU("");
        try{
            sender.send(pkt);
        }
        catch (Tins::socket_write_error){
            cout<<"Sending error \n";
            sender.send(pkt);
        }
//        std::cout << ia << endl;
    } else {
        int block_size = 8;
        int counter = ceil((float) message.length() / block_size);
        string ciphertext_complete;
        IP ip = IP(Globals::IPv4_address);
        cout<<"Message counter "<<counter<<endl;
        for (int i = 0; i < counter; i++) {
            string bin_string = message.substr(i * block_size, block_size);
            int number = stoi(bin_string, 0, 2);
            Globals::channel_message += std::to_string(number);
            ip.id(number);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::PSH);
            IP pkt = ip / tcp / RawPDU("");
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
//            std::cout << ip.id() << ' ' << ip.dst_addr() << endl;
        }
        int ia = 1000;
        ip.id(ia);
        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//        tcp.flags(Tins::TCP::PSH);
        IP pkt = ip / tcp / RawPDU("");
        try{
            sender.send(pkt);
        }
        catch (Tins::socket_write_error){
            cout<<"Sending error \n";
            sender.send(pkt);
        }
//        std::cout << ia << endl;
    }
}

void Sender::send_with_HTTP_case_method(const string message_to_send) {
    std::cout << "Storage HTTP case method" << endl;
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
//    cout << "Message to send: " << message_to_send << endl;
    string message = binaryString;
    PacketSender sender;
    stringstream ss;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            ss << "GET / HTTP/1.1\r\n"
               << "Host: google.com\r\n"
               << "Accept: application/json\r\n"
               << "\r\n\r\n";
            string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            ss.str("");
        } else {
            ss << "GET /  HTTP/1.1\r\n"
               << "host: google.com\r\n"
               << "Accept: application/json\r\n"
               << "\r\n\r\n";
            string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            ss.str("");
        }
        char buffer[1024] = {0};
        valread = read(sock, buffer, 1024);
    }
    ss << "GET /  HTTP/1.1\r\n"
       << "Host: fin.com\r\n"
       << "Accept: application/json\r\n"
       << "\r\n\r\n";
    string request = ss.str();
    send(sock, request.c_str(), request.length(), 0);
    ss.str("");
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
//    cout << "Message to send: " << word << endl << "Bin: " << binaryString << endl;
    string message = binaryString;
    PacketSender sender;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            IPv6 iPv6 = IPv6(Globals::IPv6_address);
            iPv6.hop_limit(254);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::RST);
            IPv6 pkt = iPv6 / tcp / RawPDU("");
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
//            std::cout << message[i] << endl;
        } else {
            IPv6 iPv6 = IPv6(Globals::IPv6_address);
            iPv6.hop_limit(255);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::RST);
            IPv6 pkt = iPv6 / tcp / RawPDU("");
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
//            std::cout << message[i] << endl;
        }
    }
    IPv6 iPv6 = IPv6();
    iPv6.dst_addr(Globals::IPv6_address);
    iPv6.hop_limit(100);
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//    tcp.flags(Tins::TCP::RST);
    IPv6 pkt = iPv6 / tcp / RawPDU("");
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send(pkt);
    }
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
    PacketSender sender;
    int seq = 1;
    IP ip = IP(Globals::IPv4_address);
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.seq(seq);
    IP pkt = ip / tcp / RawPDU("");
    sender.send(pkt);
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            IP ip = IP(Globals::IPv4_address);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
            seq = seq + 1;
            tcp.seq(seq);
            IP pkt = ip / tcp / RawPDU("");
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
        } else {
            IP ip = IP(Globals::IPv4_address);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
            tcp.seq(seq);
            IP pkt = ip / tcp / RawPDU("");
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
        }
    }
    tcp.seq(0);
    pkt = ip / tcp / RawPDU("");
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send(pkt);
    }
    std::cout << "Sending finished" << endl;
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
    PacketSender sender;
    int seq = 1;
    IP ip = IP(Globals::IPv4_address);
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.flags(Tins::TCP::RST);
    tcp.seq(seq);
    IP pkt = ip / tcp / RawPDU("");
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
    }
    seq = seq + 1;
    for (char i : message) {
        if (i == '0') {
            tcp.seq(seq);
            pkt = ip / tcp / RawPDU("");
            try{
                sender.send(pkt);
            }
            catch (Tins::socket_write_error){
                cout<<"Sending error \n";
            }
        }
        seq = seq + 1;
    }
    tcp.seq(seq);
    pkt = ip / tcp / RawPDU("");
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send(pkt);
    }
    tcp.seq(0);
    pkt = ip / tcp / RawPDU("");
    try{
        sender.send(pkt);
    }
    catch (Tins::socket_write_error){
        cout<<"Sending error \n";
        sender.send(pkt);
    }
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

