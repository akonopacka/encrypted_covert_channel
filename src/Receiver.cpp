#include "../include/Receiver.h"


Receiver::Receiver() {}

bool Receiver::timing_callback(const PDU &pdu) {
//    time_received = std::chrono::high_resolution_clock::now();
//    time_span = time_received - time_of_last_packet;
//    double interval = time_span.count();
////    // Find the IP layer
//    const IP &ip = pdu.rfind_pdu<IP>();
//    // Find the TCP layer
//    const UDP &udp = pdu.rfind_pdu<UDP>();
//    std::cout << udp.sport()<< ' ';
//    Tins::Packet packet = Tins::Packet(pdu);
//    Timestamp ts = packet.timestamp();
//    double timestamp = ts.seconds()*1000000 + ts.microseconds();
//    std::cout<<std::fixed<<"Seconds: "<<ts.seconds()<<"microseconds"<<ts.microseconds()<<endl;
//    double inv = timestamp - last_packet_timestamp ;
//    std::cout<<"Inter: "<< inv<<" "<< "Ts: " << timestamp << std::endl;
//
//    //    std::cout <<endl<<endl<< ip.src_addr() << ':' << udp.sport() << " -> "
////          << ip.dst_addr() << ':' << udp.dport() << "    "
////          << ip.tot_len() << endl;
////
////    if(udp.dport()==22){
//
////        time_span = time_received - time_of_last_packet;
////        double interval = time_span.count();
////        std::cout <<endl ip.src_addr() << ':' << udp.sport() << " -> "
////                  << ip.dst_addr() << ':' << udp.dport() << "    "
////                  << ip.tot_len() << endl;
//    std::cout << "Interval: " << interval<<" ";
//
//    if(inv < 1000){
//        message = message + "0";
//        std::cout << "0"<<endl;
//    }
//    else if (inv < 2000000){
//        message = message + "1";
//        std::cout << "1"<<endl;
//    }
//    else {
//        if(message!=""){
//            message.erase (0,1);
//            std::cout<<"Received message: "<<message<<endl;
//            std::stringstream sstream(message);
//            std::string output;
//            while(sstream.good())
//            {
//                std::bitset<8> bits;
//                sstream >> bits;
//                char c = char(bits.to_ulong());
//                output += c;
//            }
//            std::cout <<"Uncoded message: "<< output<<endl;
//
//            //                unsigned char ciphertext[128];
//            //                /* Buffer for the decrypted text */
//            //                unsigned char decryptedtext[128];
//            //                int decryptedtext_len, ciphertext_len;
//            //                /* Decrypt the ciphertext */
//            //
//            //                std::copy( output.begin(), output.end(), ciphertext );
//            //                ciphertext[output.length()] = 0;
//            //                std::cout << ciphertext << std::endl;
//            //                ciphertext_len = output.length()-1;
//            //
//            //                decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
//            //                                            decryptedtext);
//            //
//            //                /* Add a NULL terminator. We are expecting printable text */
//            //                decryptedtext[decryptedtext_len] = '\0';
//            //
//            //                /* Show the decrypted text */
//            //                printf("Decrypted text is:\n");
//            //                printf("%s\n", decryptedtext);
//        }
//        message = "";
//    }
////        std::cout<<"Received message: "<<message<<endl;
//    time_of_last_packet = std::chrono::high_resolution_clock::now();
//    last_packet_timestamp = ts.seconds()*1000000 + ts.microseconds();
////    }

    return true;
}
