/*
	Better description
*/
#include <string.h>
#include <string>

using std::string;

#include <vector>
#include <unistd.h>
#include <iostream>
#include <tins/tins.h>
#include <chrono>

#include <unistd.h>
//#include "include/Globals.h"
#include "include/Sender.h"
#include "include/Receiver.h"

#include <jsoncpp/json/json.h>
#include <jsoncpp/json/value.h>
#include <fstream>

using namespace Tins;
using namespace std;

std::string message_;
std::chrono::high_resolution_clock::time_point time_of_last_packet_;
std::chrono::high_resolution_clock::time_point time_received_;
std::chrono::duration<double, std::milli> time_span_;
double last_packet_timestamp_;

// "timing", "storage", "IP_id", "HTTP", "LSB", "sequence", "loss"
string covert_channel_type = "";
string message_to_send = "";


int main(int argc, char **argv) {

    Json::Value config;
    std::ifstream config_file("../config.json", std::ifstream::binary);
    config_file >> config;

    covert_channel_type = config["covert_channel_type"].asString();
    message_to_send = config["message_to_send"].asString();

    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {

            //      Configuring parameters
            Globals::interface_ = config["interface"].asString();
            Globals::IPv4_address = config["server_IPv4_address"].asString();
            Globals::dst_port_ = config["dst_port"].asInt();
            Globals::src_port_ = config["src_port"].asInt();
            Globals::time_interval_1_ms_ = config["timing_method"]["time_interval_1_ms"].asInt();
            Globals::time_interval_stop_ms_ = config["timing_method"]["time_interval_stop_ms"].asInt();
            Globals::is_encrypted = config["cryptography"]["is_encrypted"].asBool();

            Receiver receiver = Receiver();
            if (covert_channel_type == "storage") {
                std::cout << "Server! - Storage method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 1234");
                Sniffer("lo").sniff_loop(receiver.storage_callback);
            } else if (covert_channel_type == "IP_id") {
                std::cout << "Server! - IP_id method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 1234");
                Sniffer("lo").sniff_loop(receiver.IP_id_callback);
            }
            else if (covert_channel_type == "HTTP") {
                std::cout << "Server! - HTTP method\n";
                receiver.HTTP_callback();
            }
            else if (covert_channel_type == "LSB") {
                std::cout << "Server! - LSB Hop limit method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 1234");
                Sniffer("lo").sniff_loop(receiver.LSB_Hop_callback);
            }
            else if (covert_channel_type == "sequence") {
                std::cout << "Server! - sequence method\n";
                Globals::message_="";
                Globals::last_seq_ = 1;
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp.dstport==1234");
                sniffer.sniff_loop(receiver.sequence_callback);
            }
            else if (covert_channel_type == "loss") {
                std::cout << "Server! - Loss method\n";
                Globals::message_="";
                Globals::last_seq_ = 1;
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp.dstport==1234");
                sniffer.sniff_loop(receiver.loss_callback);
            }
            else if (covert_channel_type == "timing") {
                std::cout << "Server! - Timing method\n";
                string filter = "udp&&!icmp&&!dns&&udp.dstport=="+Globals::dst_port_;
                SnifferConfiguration sniffer_configuration = SnifferConfiguration();
                sniffer_configuration.set_immediate_mode(true);
                string f = "udp port "+Globals::dst_port_;
                sniffer_configuration.set_filter("udp port 1234");
                Sniffer sniffer("lo", sniffer_configuration);
                sniffer.set_filter(filter);
                sniffer.sniff_loop(receiver.timing_callback);
            }
        }
    }

    if (!strcmp(argv[1], "--client")) {
//      Configuring parameters
        Globals::IPv4_address = config["server_IPv4_address"].asString();
        Globals::dst_port_ = config["dst_port"].asInt();
        Globals::src_port_ = config["src_port"].asInt();
        Globals::time_interval_1_ms_ = config["timing_method"]["time_interval_1_ms"].asInt();
        Globals::time_interval_stop_ms_ = config["timing_method"]["time_interval_stop_ms"].asInt();
        bool is_encrypted = config["cryptography"]["is_encrypted"].asBool();
        Sender sender = Sender(covert_channel_type, is_encrypted);
        sender.send_message(message_to_send);
        return 0;
    } else {
        std::cerr << "Bad usage";
        return 1;
    }
}
