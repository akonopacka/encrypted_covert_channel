//
// Created by root on 02/11/2020.
//

#include "../include/Sender.h"

Sender::Sender(const string &message, const string &method) : message(message), method(method) {};

void Sender::send_with_timing_method(){
    std::cout<<"Timing method"<<endl;
    string word = message;
    string binaryString = "";
    for (char& _char : word) {
        binaryString +=bitset<8>(_char).to_string();
    }
    cout<<"word: "<<word<<" bin: "<<binaryString<<endl;
    message = binaryString;
    PacketSender sender;
    IP pkt = IP("127.0.0.1") / UDP(22) / RawPDU("s");
    sender.send(pkt);
    for (std::string::size_type i = 0; i < message.size(); i++) {
        if (message[i]=='0'){
            std::cout << i<<". "<< message[i] << endl;
            IP pkt = IP("127.0.0.1") / UDP(22, i) / RawPDU("s");
//                    pkt.ttl(129);
            sender.send(pkt);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        else{
            std::cout << i<<". "<<message[i] << endl;
            IP pkt = IP("127.0.0.1") / UDP(22, i) / RawPDU("s");
//                    pkt.ttl(229);
            sender.send(pkt);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
    sender.send(pkt);
    std::cout<<endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(6000));
    sender.send(pkt);
    std::cout << "Sending completed.";
}

void Sender::send_with_storage_method(){
    std::cout<<"Storage method"<<endl;
    for (std::string::size_type i = 0; i < message.size(); i++) {
        char a = message[i];
        int ia = (int)a;
        PacketSender sender;
        std::string s(ia, 'a');
        IP pkt = IP("127.0.0.1") / TCP(22) / RawPDU(s);
        sender.send(pkt);
        std::cout << message[i] << ' '<<ia<<endl;
    }
    PacketSender sender;
    int ia = (int)'0';
    std::string s(ia, 'a');
    IP pkt = IP("127.0.0.1") / TCP(22) / RawPDU(s);
    sender.send(pkt);
    std::cout << '0' << ' '<<ia<<endl;

}