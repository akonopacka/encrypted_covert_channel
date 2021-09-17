//
// Created by root on 02/11/2020.
//

#include "../include/Sender.h"

Sender::Sender(const string &method, bool is_encrypted, string cipher_type) : method(method),
                                                                              is_encrypted(is_encrypted),
                                                                              cipher_type(cipher_type) {}

void Sender::send_with_timing_method(const string message_to_send) {
    std::cout << "Timing method" << endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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

    cout << "Bin: " << binaryString << endl;
    message = binaryString;
    PacketSender sender;
    IP pkt = IP(Globals::IPv4_address) / UDP(Globals::dst_port_, Globals::src_port_) / RawPDU("s");
    sender.send(pkt);
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            std::cout << i << ". " << message[i] << endl;
            IP pkt = IP(Globals::IPv4_address) / UDP(Globals::dst_port_, Globals::src_port_) / RawPDU("s");
            sender.send(pkt);
        } else {
            std::cout << i << ". " << message[i] << endl;
            IP pkt = IP(Globals::IPv4_address) / UDP(Globals::dst_port_, Globals::src_port_) / RawPDU("s");
            sender.send(pkt);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
    sender.send(pkt);
    std::cout << endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    sender.send(pkt);
    std::cout << "Sending completed.";
}

void Sender::send_with_storage_method(const string message_to_send) {
    std::cout << "Storage method" << endl;
    std::cout << "Sending message:" << message_to_send << endl;
    string message = "";
    if (!is_encrypted) {
        message = message_to_send;
        for (std::string::size_type i = 0; i < message.size(); i++) {
            char a = message[i];
            int ia = (int) a;
            PacketSender sender;
            std::string s(ia, 'a');
            IP pkt = IP(Globals::IPv4_address) / TCP(Globals::dst_port_, Globals::src_port_) / RawPDU(s);
            sender.send(pkt);
        }
        PacketSender sender;
        int ia = 1;
        std::string s(ia, 'a');
        IP pkt = IP(Globals::IPv4_address) / TCP(Globals::dst_port_, Globals::src_port_) / RawPDU(s);
        sender.send(pkt);
    } else {
        message = message_to_send;
        int block_size = 8;
        int counter = ceil((float) message.length() / block_size);
        string ciphertext_complete;
        for (int i = 0; i < counter; i++) {
            string bin_string = message.substr(i * block_size, block_size);
            int number = stoi(bin_string, 0, 2);
            PacketSender sender;
            std::string s(number, 'a');
            IP pkt = IP(Globals::IPv4_address) / TCP(Globals::dst_port_, Globals::src_port_) / RawPDU(s);
            sender.send(pkt);
//            cout<<"Send : "<< number << " " <<  bin_string << endl;
        }
        PacketSender sender;
        int ia = 1;
        std::string s(ia, 'a');
        IP pkt = IP(Globals::IPv4_address) / TCP(Globals::dst_port_, Globals::src_port_) / RawPDU(s);
        sender.send(pkt);
    }
}

void Sender::send_with_storage_method_IP_id(const string message_to_send) {
    std::cout << "Storage IP_id method" << endl;
    string word = message_to_send;
    string binaryString = "";

    string message = "";

    if (!is_encrypted) {
        message = message_to_send;
    } else {
        std::stringstream sstream(message_to_send);
        std::string output;
        while (sstream.good()) {
            std::bitset<8> bits;
            sstream >> bits;
            char c = char(bits.to_ulong());
            message += c;
        }
    }

    cout << "Message to send: " << message << endl;
    PacketSender sender;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        char a = message[i];
        int ia = (int) a;
        IP ip = IP(Globals::IPv4_address);
        ip.id(ia);
        ip.ttl(100);
        TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
        tcp.flags(Tins::TCP::RST);
        IP pkt = ip / tcp / RawPDU("");
        sender.send(pkt);
        std::cout << message[i] << ' ' << ia << endl;
    }
    char a = '0';
    int ia = (int) a;
    IP ip = IP(Globals::IPv4_address);
    ip.id(ia);
    ip.ttl(100);
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.flags(Tins::TCP::RST);
    IP pkt = ip / tcp / RawPDU("");
    sender.send(pkt);
    std::cout << '0' << ' ' << ia << endl;
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

    // Convert IPv4 and IPv6 addresses from text to binary form
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

    cout << "Message to send: " << message_to_send << endl;
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

    cout << "Message to send: " << word << endl << "Bin: " << binaryString << endl;
    string message = binaryString;
    PacketSender sender;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            IPv6 iPv6 = IPv6("::1");
            iPv6.hop_limit(254);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::RST);
            IPv6 pkt = iPv6 / tcp / RawPDU("");
            sender.send(pkt);
//            std::cout << message[i] << endl;
        } else {
            IPv6 iPv6 = IPv6();
            iPv6.dst_addr("::1");
            iPv6.hop_limit(255);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//            tcp.flags(Tins::TCP::RST);
            IPv6 pkt = iPv6 / tcp / RawPDU("");
            sender.send(pkt);
//            std::cout << message[i] << endl;
        }
    }
    IPv6 iPv6 = IPv6();
    iPv6.dst_addr("::1");
    iPv6.hop_limit(100);
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
//    tcp.flags(Tins::TCP::RST);
    IPv6 pkt = iPv6 / tcp / RawPDU("");
    sender.send(pkt);
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
    cout << "Message to send: " << word << endl << "Bin: " << binaryString << endl;
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
            sender.send(pkt);
        } else {
            IP ip = IP(Globals::IPv4_address);
            TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
            tcp.seq(seq);
            IP pkt = ip / tcp / RawPDU("");
            sender.send(pkt);
        }
    }
    tcp.seq(0);
    pkt = ip / tcp / RawPDU("");
    sender.send(pkt);
    std::cout << "Sending finished" << endl;
}

void Sender::send_with_loss_method(const string message_to_send) {
    std::cout << "Loss method" << endl;
    cout << "Configuration: " << Globals::IPv4_address << " " << Globals::dst_port_ << " " << Globals::src_port_
         << endl;
    string word = message_to_send;
    string binaryString = "";
    if (!is_encrypted) {
        for (char &_char: word) {
            binaryString += bitset<8>(_char).to_string();
        }
    } else {
        binaryString = message_to_send;
    }
    cout << "Bin: " << binaryString << endl;
    string message = binaryString;
    PacketSender sender;
    int seq = 1;
    IP ip = IP(Globals::IPv4_address);
    TCP tcp = TCP(Globals::dst_port_, Globals::src_port_);
    tcp.flags(Tins::TCP::RST);
    tcp.seq(seq);
    IP pkt = ip / tcp / RawPDU("");
    sender.send(pkt);
    seq = seq + 1;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i] == '0') {
            tcp.seq(seq);
            IP pkt = ip / tcp / RawPDU("");
            sender.send(pkt);
        }
        seq = seq + 1;
    }
    tcp.seq(seq);
    pkt = ip / tcp / RawPDU("");
    sender.send(pkt);
    tcp.seq(0);
    pkt = ip / tcp / RawPDU("");
    sender.send(pkt);
    std::cout << "Sending finished" << endl;
}

void Sender::send_message(string message_to_send) {
    std::cout << "Sending method: " << method << ", Message is encrypted: " << std::boolalpha << is_encrypted << endl;
    message_to_send +=char(0);
    std::string duration_of_encryption = "----";
    if (is_encrypted) {
        Cryptographer cryptographer = Cryptographer(cipher_type);
        // Get starting timepoint
        auto start = high_resolution_clock::now();
        message_to_send = cryptographer.encrypt(message_to_send);
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        duration_of_encryption = std::to_string(duration.count());
        std::cout << "Encrypted message: " << message_to_send <<  endl;
    }
    float message_entropy = Evaluation::calculate_entropy(message_to_send);

    // Get starting timepoint
    auto start = high_resolution_clock::now();
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
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    std::string time_of_sending = "";
    time_of_sending = std::to_string(duration.count());
    cout << "Time taken by sending function: " << time_of_sending << " microseconds" << endl;

//    Save results to file
    std:string results = "Calculated message entropy: " + std::to_string(message_entropy) + "\n";
    results += "Time taken by encrypting function: " + duration_of_encryption + " microseconds\n";
    results += "Time taken by sending function: " + time_of_sending + " microseconds\n";
    std::cout << "Results: " << results << std::endl;
    Evaluation::save_results_to_file(results, Globals::results_path, method, "client");
}

