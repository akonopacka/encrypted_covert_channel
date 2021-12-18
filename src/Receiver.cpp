#include "../include/Receiver.h"


Receiver::Receiver() {
    Globals::message_ = "";
    Globals::last_seq_ = 1;
//    Print configuration of server
    std::cout << "Server! - " << Globals::covert_channel_type_ << " method\n";
    std::cout << "Is encrypted - ";
    printf(Globals::is_encrypted ? "true" : "false");
    std::cout << " \n\n";
    if (Globals::covert_channel_type_ == "storage") {
        std::cout << "Server! - Storage method\n";
        Sniffer sniffer(Globals::interface_);
        sniffer.set_filter("tcp&&port 1234");
        Sniffer(Globals::interface_).sniff_loop(storage_callback);
    } else if (Globals::covert_channel_type_ == "IP_id") {
        std::cout << "Server! - IP_id method\n";
        Sniffer sniffer(Globals::interface_);
        sniffer.set_filter("tcp&&port 1234");
        Sniffer(Globals::interface_).sniff_loop(IP_id_callback);
    } else if (Globals::covert_channel_type_ == "HTTP") {
        std::cout << "Server! - HTTP method\n";
        HTTP_callback();
    } else if (Globals::covert_channel_type_ == "LSB") {
        std::cout << "Server! - LSB Hop limit method\n";
        Sniffer sniffer(Globals::interface_);
        sniffer.set_filter("tcp&&port 1234");
        Sniffer(Globals::interface_).sniff_loop(LSB_Hop_callback);
    } else if (Globals::covert_channel_type_ == "sequence") {
        std::cout << "Server! - sequence method\n";
        Sniffer sniffer(Globals::interface_);
        sniffer.set_filter("tcp.dstport==1234");
        sniffer.sniff_loop(sequence_callback);
    } else if (Globals::covert_channel_type_ == "loss") {
        std::cout << "Server! - Loss method\n";
        Sniffer sniffer(Globals::interface_);
        sniffer.set_filter("tcp.dstport==1234");
        sniffer.sniff_loop(loss_callback);
    } else if (Globals::covert_channel_type_ == "timing") {
        std::cout << "Server! - Timing method\n";
        SnifferConfiguration sniffer_configuration = SnifferConfiguration();
        sniffer_configuration.set_immediate_mode(true);
        sniffer_configuration.set_promisc_mode(true);
        sniffer_configuration.set_timeout(50);
        string filter = "udp and dst port " + to_string(Globals::dst_port_) + " and ip src " + Globals::IPv4_address;
        std::cout << "Filter : " << filter << "\n";
        sniffer_configuration.set_filter(filter);
        Sniffer sniffer(Globals::interface_, sniffer_configuration);
        sniffer.sniff_loop(timing_callback);
    }
}

bool Receiver::timing_callback(const PDU &pdu) {
    Globals::time_received_ = std::chrono::high_resolution_clock::now();
    Globals::time_span_ = Globals::time_received_ - Globals::time_of_last_packet_;
    const IP &ip = pdu.rfind_pdu<IP>();
    const UDP &udp = pdu.rfind_pdu<UDP>();
    std::cout << "Address: " << ip.src_addr() << " " << udp.dport() << std::endl;
    if (udp.dport() == Globals::dst_port_) {
        Tins::Packet packet = Tins::Packet(pdu);
        Timestamp ts = packet.timestamp();
        long timestamp = ts.seconds() * 1000000 + ts.microseconds();
//        std::cout << std::fixed << "Timestamp: " << timestamp << " Seconds: " << ts.seconds() << " microseconds:"
//                  << ts.microseconds() << endl;
        long interval = timestamp - Globals::last_packet_timestamp_;
        std::cout << "Inter: " << interval << " " << "Ts: " << timestamp << std::endl;
        if (!Globals::is_started_receiving) {
            Globals::start_receiving = high_resolution_clock::now();
            Globals::is_started_receiving = true;
        }
        if (interval < (Globals::time_interval_1_ms_)) {
            Globals::message_ = Globals::message_ + "0";
            std::cout << Globals::timing_counter << ". 0" << endl;
            Globals::timing_counter += 1;
        } else if (interval < 4500000) {
            Globals::message_ = Globals::message_ + "1";
            std::cout << Globals::timing_counter << ". 1" << endl;
            Globals::timing_counter += 1;
        } else {
            if (Globals::message_ != "") {
                Globals::stop_receiving = high_resolution_clock::now();
                Globals::message_.erase(0, 1);
                std::stringstream sstream(Globals::message_);
                std::string output;
                while (sstream.good()) {
                    std::bitset<8> bits;
                    sstream >> bits;
                    char c = char(bits.to_ulong());
                    output += c;
                }

                std::string original_message = Globals::original_message_;
                std::string received_message = output;
                auto duration = duration_cast<microseconds>(Globals::stop_receiving - Globals::start_receiving);
                int sent_bits = Globals::message_.length();

//                std::string results = "Capacity:  " + std::to_string(capacity) + " b/s\n";
//                results += "Time taken for receiving: " + std::to_string(duration.count()) + " microseconds\n";
                string duration_of_decryption;
                if (Globals::is_encrypted) {
                    Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
                    auto start_decryption = high_resolution_clock::now();
                    string decrypted_message = cryptographer.decrypt(Globals::message_);
                    auto stop_decryption = high_resolution_clock::now();
                    auto decryption_duration = duration_cast<microseconds>(stop_decryption - start_decryption);
                    duration_of_decryption = std::to_string(decryption_duration.count());
                    //                remove padding
                    std::size_t pos = decrypted_message.find(char(0));
                    if (pos != string::npos) {
                        int len = decrypted_message.length();
                        received_message = decrypted_message.erase(pos, len);
                    } else {
                        received_message = decrypted_message;
                    }
                }
                std::cout << "Encoded message: " << output << endl;
                std::cout << "Received message: " << received_message << endl;
//          calculate channel capacity based on messages sent in channel

                float capacity_channel = float(sent_bits) / (duration.count() * 0.001);
//          calculate channel capacity based on original message
                float capacity_based_on_original_message = float(received_message.length()-1) * 8 / (duration.count() * 0.001);
//            Calculate BER
                float BER = Evaluation::get_BER(original_message, received_message);

//                Evaluation::save_results_to_file(results, Globals::results_path, "timing", "server");
                //            Saving to general file
                std::string combined_results_path = Globals::results_path;
                combined_results_path += "_server_timing_" + Globals::cipher_type_ + ".csv";
                string message_path = Globals::results_path + "_server_timing_" + Globals::cipher_type_ + "_message.csv";

                //              Write the column names to result file
                std::ifstream infile(combined_results_path);
                bool file_exists = infile.good();
                if (!file_exists){
                    std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
                    infile_stream << "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]\n";
                }

                std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
                string results = std::to_string(BER) + ";" + std::to_string(capacity_channel) + ";"
                                 + std::to_string(capacity_based_on_original_message) + ";" +
                                 std::to_string(duration.count()) + ";"
                                 + duration_of_decryption +"\n";
                log << results;
                std::cout << "General results saved to : " << combined_results_path << std::endl;
                std::cout<< "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]"<<endl;
                std::cout << results << std::endl;
                log.close();
                std::ofstream log_message(message_path, std::ios_base::app | std::ios_base::out);
                log_message << Globals::last_packet_timestamp_<<";"<<Globals::message_<<endl;
                log_message.close();
                Globals::is_started_receiving = false;
                Globals::timing_counter = 0;
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
        if (!Globals::is_started_receiving) {
            Globals::start_receiving = high_resolution_clock::now();
            Globals::is_started_receiving = true;
        }
        if (a == 500) {
            Globals::stop_receiving = high_resolution_clock::now();
            std::string received_message = Globals::message_;
            std::cout << "Original received message: " << Globals::message_ << std::endl;
            string duration_of_decryption;
            int sent_bits = 0;
            if (Globals::is_encrypted) {
                Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
                auto start_decryption = high_resolution_clock::now();
                string decrypted_message = cryptographer.decrypt(Globals::message_);
                auto stop_decryption = high_resolution_clock::now();
                auto decryption_duration = duration_cast<microseconds>(stop_decryption - start_decryption);
                duration_of_decryption = std::to_string(decryption_duration.count());
                //                remove padding
                std::size_t pos = decrypted_message.find(char(0));
                if (pos != string::npos) {
                    int len = decrypted_message.length();
                    received_message = decrypted_message.erase(pos, len);
                } else {
                    received_message = decrypted_message;
                }
                sent_bits = Globals::message_.length();
            }
            else{
                sent_bits = Globals::message_.length()*8;
            }
            std::cout << "Received message: " << received_message << std::endl;
            std::cout << "Received message: " << Globals::message_ << endl;
            auto duration = duration_cast<microseconds>(Globals::stop_receiving - Globals::start_receiving);
//          calculate channel capacity based on messages sent in channel
            float capacity_channel = float(sent_bits) / (duration.count() * 0.001);
//          calculate channel capacity based on original message
            float capacity_based_on_original_message =
                    float(received_message.length()) * 8 / (duration.count() * 0.001);
//            Calculate BER
            std::string original_message = Globals::original_message_;
            float BER = Evaluation::get_BER(original_message, received_message);
            //            Saving to general file
            std::string combined_results_path = Globals::results_path;
            combined_results_path += "_server_storage_" + Globals::cipher_type_ + ".csv";

            //              Write the column names to result file
            std::ifstream infile(combined_results_path);
            bool file_exists = infile.good();
            if (!file_exists){
                std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
                infile_stream << "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]\n";
            }

            std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
            string results = std::to_string(BER) + ";" + std::to_string(capacity_channel) + ";"
                             + std::to_string(capacity_based_on_original_message) + ";" +
                             std::to_string(duration.count()) + ";"
                             + duration_of_decryption + "\n";
            log << results;
            std::cout << "General results saved to : " << combined_results_path << std::endl;
            std::cout<< "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]"<<endl;
            std::cout << results << std::endl;
            log.close();
            Globals::message_ = "";
            Globals::is_started_receiving = false;
        } else {
            if (Globals::is_encrypted) {
                string bin_string = bitset<8>(a).to_string();
                Globals::message_ = Globals::message_ + bin_string;
//                cout<<"Received : "<< a << " " <<  bitset<8>(a).to_string() << endl;
            } else
                Globals::message_ = Globals::message_ + c;
        }
    }
    return true;
}

bool Receiver::IP_id_callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    if (tcp.dport() == Globals::dst_port_) {
        if (!Globals::is_started_receiving) {
            Globals::start_receiving = high_resolution_clock::now();
            Globals::is_started_receiving = true;
        }
//        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
//                  << ip.dst_addr() << ':' << tcp.dport() << "    "
//                  << ip.id() << endl;
        int a = ip.id();
        char c = static_cast<char>(a);
        if (a == 1000) {
            Globals::stop_receiving = high_resolution_clock::now();
            string received_message = "";
//            std::cout << "Original received message: " << Globals::message_ << std::endl;
            string duration_of_decryption;
            int sent_bits = 0;
            if (Globals::is_encrypted) {
                Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
                auto start_decryption = high_resolution_clock::now();
                string decrypted_message = cryptographer.decrypt(Globals::message_);
                auto stop_decryption = high_resolution_clock::now();
                auto decryption_duration = duration_cast<microseconds>(stop_decryption - start_decryption);
                duration_of_decryption = std::to_string(decryption_duration.count());
                //                remove padding
                std::size_t pos = decrypted_message.find(char(0));
                if (pos != string::npos) {
                    int len = decrypted_message.length();
                    received_message = decrypted_message.erase(pos, len);
                } else {
                    received_message = decrypted_message;
                }
                sent_bits = Globals::message_.length();
            } else {
                string received_message_ = Globals::message_;
                std::size_t pos = received_message_.find(char(0));
                if (pos != string::npos) {
                    int len = received_message_.length();
                    received_message_ = received_message_.erase(pos, len);
                }
                else {
                    received_message = received_message_;
                }
                sent_bits = Globals::message_.length()*8;
            }

            std::cout << "Received message: " << received_message << std::endl;
            auto duration = duration_cast<microseconds>(Globals::stop_receiving - Globals::start_receiving);
//          calculate channel capacity based on messages sent in channel
            float capacity_channel = float(sent_bits) / (duration.count() * 0.001);
//          calculate channel capacity based on original message
            float capacity_based_on_original_message =
                    float(received_message.length()) * 8 / (duration.count() * 0.001);

//            Calculate BER
            std::string original_message = Globals::original_message_;
            float BER = Evaluation::get_BER(original_message, received_message);

            //            Saving to general file
            std::string combined_results_path = Globals::results_path;
            combined_results_path += "_server_IP_id_" + Globals::cipher_type_ + ".csv";

            //              Write the column names to result file
            std::ifstream infile(combined_results_path);
            bool file_exists = infile.good();
            if (!file_exists){
                std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
                infile_stream << "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]\n";
            }

            std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
            string results = std::to_string(BER) + ";" + std::to_string(capacity_channel) + ";"
                             + std::to_string(capacity_based_on_original_message) + ";" +
                             std::to_string(duration.count()) + ";"
                             + duration_of_decryption + "\n";
            log << results;
            std::cout << "General results saved to : " << combined_results_path << std::endl;
            std::cout<< "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]"<<endl;
            std::cout << results << std::endl;
            log.close();
            Globals::message_ = "";
            Globals::is_started_receiving = false;
        } else {
            if (Globals::is_encrypted) {
                string bin_string = bitset<8>(a).to_string();
                if (a > 255)
                    bin_string = "00000000";
                Globals::message_ = Globals::message_ + bin_string;
//                cout<<"Received : "<< a << " " <<  bin_string << endl;
            } else
                Globals::message_ = Globals::message_ + c;
        }
    }
    return true;
}

template<typename Container>
bool in_quote(const Container &cont, const std::string &s) {
    return std::search(cont.begin(), cont.end(), s.begin(), s.end()) != cont.end();
}

void Receiver::HTTP_callback() {
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

// Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

// Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(Globals::dst_port_);

// Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *) &address,
             sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *) &address,
                             (socklen_t *) &addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    bool end = false;
    while (!end) {
        if (!Globals::is_started_receiving) {
            Globals::start_receiving = high_resolution_clock::now();
            Globals::is_started_receiving = true;
        }
        char buffer[1024] = {0};
        valread = read(new_socket, buffer, 1024);
        if (valread == 0)
            continue;
        else {
            string str(buffer);
            memset(buffer, 0, 1024);
            if (str.find("fin.com") != string::npos) {
                Globals::stop_receiving = high_resolution_clock::now();
                std::stringstream sstream(Globals::message_);
                std::string output;
                while (sstream.good()) {
                    std::bitset<8> bits;
                    sstream >> bits;
                    char c = char(bits.to_ulong());
                    output += c;
                }
                string received_message = "";
                string duration_of_decryption;
                if (Globals::is_encrypted) {
                    Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
                    auto start_decryption = high_resolution_clock::now();
                    string decrypted_message = cryptographer.decrypt(Globals::message_);
                    auto stop_decryption = high_resolution_clock::now();
                    auto decryption_duration = duration_cast<microseconds>(stop_decryption - start_decryption);
                    duration_of_decryption = std::to_string(decryption_duration.count());
                    //                remove padding
                    std::size_t pos = decrypted_message.find(char(0));
                    if (pos != string::npos) {
                        int len = decrypted_message.length();
                        received_message = decrypted_message.erase(pos, len);
                    } else {
                        received_message = decrypted_message;
                    }
                } else
                    received_message = output;
                std::cout << "Received unencrypted message: " << output << std::endl;
                std::cout << "Received message: " << received_message << std::endl;

                auto duration = duration_cast<microseconds>(Globals::stop_receiving - Globals::start_receiving);
                int sent_bits = Globals::message_.length();
//          calculate channel capacity based on messages sent in channel
                float capacity_channel = float(sent_bits) / (duration.count() * 0.001);
//          calculate channel capacity based on original message
                float len = received_message.length();
                if (!Globals::is_encrypted){
                    len = float(received_message.length()-1);
                }

                float capacity_based_on_original_message =
                        float(len) * 8 / (duration.count() * 0.001);

//            Calculate BER
                std::string original_message = Globals::original_message_;
                float BER = Evaluation::get_BER(original_message, received_message);
                //            Saving to general file
                std::string combined_results_path = Globals::results_path;
                combined_results_path += "_server_HTTP_" + Globals::cipher_type_ + ".csv";

//              Write the column names to result file
                std::ifstream infile(combined_results_path);
                bool file_exists = infile.good();
                if (!file_exists){
                    std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
                    infile_stream << "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]\n";
                }

                std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
                string results = std::to_string(BER) + ";" + std::to_string(capacity_channel) + ";"
                                 + std::to_string(capacity_based_on_original_message) + ";" +
                                 std::to_string(duration.count()) + ";"
                                 + duration_of_decryption + "\n";
                log << results;
                std::cout << "General results saved to : " << combined_results_path << std::endl;
                std::cout<< "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]"<<endl;
                std::cout << results << std::endl;
                log.close();

                Globals::message_ = "";
                Globals::is_started_receiving = false;
                str = "";
                if ((new_socket = accept(server_fd, (struct sockaddr *) &address,
                                         (socklen_t *) &addrlen)) < 0) {
                    perror("accept");
                    exit(EXIT_FAILURE);
                }
            } else {
                string s = "Host:";
                bool is_Host = in_quote(str, s);
                s = "host:";
                bool is_host = in_quote(str, s);
                if (is_Host) {
                    Globals::message_ = Globals::message_ + '0';
                    str = "";
                } else if (is_host) {
                    Globals::message_ = Globals::message_ + '1';
                    str = "";
                }
                send(new_socket, "Hello from server", strlen("Hello from server"), 0);
            }
            memset(buffer, 0, 1024);
        }
    }
}

bool Receiver::LSB_Hop_callback(const PDU &pdu) {
    const IPv6 &ip = pdu.rfind_pdu<IPv6>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();

//    std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
//              << ip.dst_addr() << ':' << tcp.dport() << "    "
//              << ip.hop_limit() << endl;
    int a = ip.hop_limit();

    if (a != 100) {
        if (!Globals::is_started_receiving) {
            Globals::start_receiving = high_resolution_clock::now();
            Globals::is_started_receiving = true;
        }
        Globals::message_ = Globals::message_ + to_string(a & 1);
    } else {
        Globals::stop_receiving = high_resolution_clock::now();
        std::stringstream sstream(Globals::message_);
        std::string output;
        while (sstream.good()) {
            std::bitset<8> bits;
            sstream >> bits;
            char c = char(bits.to_ulong());
            output += c;
        }
        std::string received_message = "";
        string duration_of_decryption;
        if (Globals::is_encrypted) {
            Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
            auto start_decryption = high_resolution_clock::now();
            string decrypted_message = cryptographer.decrypt(Globals::message_);
            auto stop_decryption = high_resolution_clock::now();
            auto decryption_duration = duration_cast<microseconds>(stop_decryption - start_decryption);
            duration_of_decryption = std::to_string(decryption_duration.count());
            //                remove padding
            std::size_t pos = decrypted_message.find(char(0));
            if (pos != string::npos) {
                int len = decrypted_message.length();
                received_message = decrypted_message.erase(pos, len);
            } else {
                received_message = decrypted_message;
            }
        } else {
            received_message = output;
        }
        std::cout << "Received unencrypted message: " << output << std::endl;
        std::cout << "Received message: " << received_message << std::endl;


        auto duration = duration_cast<microseconds>(Globals::stop_receiving - Globals::start_receiving);
        int sent_bits = Globals::message_.length();
//          calculate channel capacity based on messages sent in channel
        float capacity_channel = float(sent_bits) / (duration.count() * 0.001);
//          calculate channel capacity based on original message
        float len = received_message.length();
        if (!Globals::is_encrypted){
            len = float(received_message.length()-1);
        }

        float capacity_based_on_original_message = float(len) * 8 / (duration.count() * 0.001);

//            Calculate BER
        std::string original_message = Globals::original_message_;
        float BER = Evaluation::get_BER(original_message, received_message);

        //            Saving to general file
        std::string combined_results_path = Globals::results_path;
        combined_results_path += "_server_LSB_" + Globals::cipher_type_ + ".csv";

        //              Write the column names to result file
        std::ifstream infile(combined_results_path);
        bool file_exists = infile.good();
        if (!file_exists){
            std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
            infile_stream << "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]\n";
        }

        std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
        std:string results = std::to_string(BER) + ";" + std::to_string(capacity_channel) + ";"
                         + std::to_string(capacity_based_on_original_message) + ";" + std::to_string(duration.count()) +
                         ";"
                         + duration_of_decryption + "\n";
        log << results;
        std::cout << "General results saved to : " << combined_results_path << std::endl;
        std::cout<< "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]"<<endl;
        std::cout << results << std::endl;

        Globals::message_ = "";
        Globals::is_started_receiving = false;
    }
    return true;
}

bool Receiver::sequence_callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if (tcp.dport() == Globals::dst_port_) {
//        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
//                  << ip.dst_addr() << ':' << tcp.dport() << "    "
//                  << tcp.seq() << endl;
        int seq = tcp.seq();
        if (!Globals::is_started_receiving) {
            Globals::start_receiving = high_resolution_clock::now();
            Globals::is_started_receiving = true;
        }
        if (seq == 0) {
            Globals::stop_receiving = high_resolution_clock::now();
            Globals::message_.erase(0, 1);
            std::stringstream sstream(Globals::message_);
            std::string output;
            while (sstream.good()) {
                std::bitset<8> bits;
                sstream >> bits;
                char c = char(bits.to_ulong());
                output += c;
            }
            Globals::last_seq_ = 0;
            std::string received_message = "";
            string duration_of_decryption;

            if (Globals::is_encrypted) {
                Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
                auto start_decryption = high_resolution_clock::now();
                string decrypted_message = cryptographer.decrypt(Globals::message_);
                auto stop_decryption = high_resolution_clock::now();
                auto decryption_duration = duration_cast<microseconds>(stop_decryption - start_decryption);
                duration_of_decryption = std::to_string(decryption_duration.count());
                //                remove padding
                std::size_t pos = decrypted_message.find(char(0));
                if (pos != string::npos) {
                    int len = decrypted_message.length();
                    received_message = decrypted_message.erase(pos, len);
                } else {
                    received_message = decrypted_message;
                }
            } else {
                received_message = output;
            }
            std::cout << "Received message: " << received_message << std::endl;
            std::cout << "Global message: " << Globals::message_ << std::endl << output << std::endl;

            auto duration = duration_cast<microseconds>(Globals::stop_receiving - Globals::start_receiving);
            int sent_bits = Globals::message_.length();
            float len = received_message.length();
            if (!Globals::is_encrypted){
                len = float(received_message.length()-1);
            }

//          calculate channel capacity based on messages sent in channel
            float capacity_channel = float(sent_bits) / (duration.count() * 0.001);
//          calculate channel capacity based on original message
            float capacity_based_on_original_message = float(len) * 8 / (duration.count() * 0.001);

//            Calculate BER
            std::string original_message = Globals::original_message_;
            float BER = Evaluation::get_BER(original_message, received_message);

            //            Saving to general file
            std::string combined_results_path = Globals::results_path;
            combined_results_path += "_server_sequence_" + Globals::cipher_type_ + ".csv";

            //              Write the column names to result file
            std::ifstream infile(combined_results_path);
            bool file_exists = infile.good();
            if (!file_exists){
                std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
                infile_stream << "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]\n";
            }

            std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
            string results = std::to_string(BER) + ";" + std::to_string(capacity_channel) + ";"
                             + std::to_string(capacity_based_on_original_message) + ";" +
                             std::to_string(duration.count()) + ";"
                             + duration_of_decryption + "\n";
            log << results;
            std::cout << "General results saved to : " << combined_results_path << std::endl;
            std::cout<< "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]"<<endl;
            std::cout << results << std::endl;

            Globals::message_ = "";
            Globals::is_started_receiving = false;
        } else {
            if (seq == Globals::last_seq_ + 1) {
                Globals::message_ = Globals::message_ + '0';
                Globals::last_seq_ = seq;
            } else {
                Globals::message_ = Globals::message_ + '1';
            }
        }
    }
    return true;
}

bool Receiver::loss_callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>();
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if (tcp.dport() == Globals::dst_port_) {
        int seq = tcp.seq();
        if (seq == 0) {
            Globals::stop_receiving = high_resolution_clock::now();
            Globals::message_.pop_back();
            std::stringstream sstream(Globals::message_);
            std::string output;

            while (sstream.good()) {
                std::bitset<8> bits;
                sstream >> bits;
                char c = char(bits.to_ulong());
                output += c;
            }
            Globals::last_seq_ = 1;
//            std::cout << "Received message: bin " << Globals::message_ << " len: " << Globals::message_.length()
//                      << endl;
            std::string received_message = output;
            string duration_of_decryption;

            if (Globals::is_encrypted) {
                Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
                auto start_decryption = high_resolution_clock::now();
                string decrypted_message = cryptographer.decrypt(Globals::message_);
                auto stop_decryption = high_resolution_clock::now();
                auto decryption_duration = duration_cast<microseconds>(stop_decryption - start_decryption);
                duration_of_decryption = std::to_string(decryption_duration.count());
                //                remove padding
                std::size_t pos = decrypted_message.find(char(0));
                std::cout << "Decrypted message: " << decrypted_message << std::endl;
                if (pos != string::npos) {
                    int len = decrypted_message.length();
                    received_message = decrypted_message.erase(pos, len);
                } else {
                    received_message = decrypted_message;
                }
            }
            std::cout << "Received message: " << received_message << std::endl;
            auto duration = duration_cast<microseconds>(Globals::stop_receiving - Globals::start_receiving);
            float len = received_message.length();
            if (!Globals::is_encrypted){
                len = float(received_message.length()-1);
            }
            int sent_bits = Globals::message_.length();

//          calculate channel capacity based on messages sent in channel
            float capacity_channel = float(sent_bits) / (duration.count() * 0.001);
//          calculate channel capacity based on original message
            float capacity_based_on_original_message = float(len) * 8 / (duration.count() * 0.001);

//            Calculate BER
            std::string original_message = Globals::original_message_;

//          BER for channel (compare message send via channel and received)
            float BER = Evaluation::get_BER(original_message, received_message);

//            Saving to general file
            std::string combined_results_path = Globals::results_path;
            combined_results_path += "_server_loss_" + Globals::cipher_type_ + ".csv";

            //  Write the column names to result file
            std::ifstream infile(combined_results_path);
            bool file_exists = infile.good();
            if (!file_exists){
                std::ofstream infile_stream(combined_results_path, std::ios_base::app | std::ios_base::out);
                infile_stream << "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]\n";
            }

            std::ofstream log(combined_results_path, std::ios_base::app | std::ios_base::out);
            string results = std::to_string(BER) + ";" + std::to_string(capacity_channel) + ";"
                             + std::to_string(capacity_based_on_original_message) + ";" +
                             std::to_string(duration.count()) + ";"
                             + duration_of_decryption + "\n";
            log << results;
            std::cout << "General results saved to : " << combined_results_path << std::endl;
            std::cout<< "BER;capacity_channel[bits/ms];capacity_based_on_original_message[bits/ms];sending_duration[ns];duration_of_decryption[ns]"<<endl;
            std::cout << results << std::endl;
            log.close();
            Globals::message_ = "";
            Globals::is_started_receiving = false;
        } else {
            if (!Globals::is_started_receiving) {
                Globals::start_receiving = high_resolution_clock::now();
                Globals::is_started_receiving = true;
            }

            if (seq != 1) {
                int i = seq - Globals::last_seq_;
                if (i == 1) {
                    Globals::message_ = Globals::message_ + '0';
                    Globals::last_seq_ = seq;
                } else {
                    std::string s(i - 1, '1');
                    Globals::message_ = Globals::message_ + s + '0';
                    Globals::last_seq_ = Globals::last_seq_ + i;
                }
            }
        }
    }
    return true;
}

