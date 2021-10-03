//
// Created by root on 20/12/2020.
//
#include <chrono>
#include <string>
#include "../include/Globals.h"

using std::string;
namespace Globals{
    std::chrono::high_resolution_clock::time_point time_of_last_packet_ = std::chrono::system_clock::from_time_t(0);
    std::chrono::high_resolution_clock::time_point time_received_= std::chrono::system_clock::from_time_t(0);
    std::chrono::duration<double, std::milli> time_span_= Globals::time_received_ - Globals::time_of_last_packet_;
    std::chrono::high_resolution_clock::time_point start_receiving = std::chrono::system_clock::from_time_t(0);
    std::chrono::high_resolution_clock::time_point stop_receiving = std::chrono::system_clock::from_time_t(0);
    double last_packet_timestamp_ = 0;
    int last_seq_ = 0;
    std::string message_ = "";
    std::string results_path = "";
    std::string original_message_ = "";
    std::string interface_ = "lo";
    std::string IPv4_address = "127.0.0.1";
    int number_of_repeat_ = 1;
    int src_port_ = 1111;
    int dst_port_= 1111;
    int time_interval_1_ms_ = 1100;
    int time_interval_stop_ms_ = 6000;
    bool is_encrypted = false;
    bool is_started_receiving = false;
    std::string cipher_type_ = "";
    std::string covert_channel_type_ = "loss";
    std::string channel_message = "";

    void load_globals(Json::Value config) {
        Globals::interface_ = config["interface"].asString();
        Globals::IPv4_address = config["server_IPv4_address"].asString();
        Globals::dst_port_ = config["dst_port"].asInt();
        Globals::src_port_ = config["src_port"].asInt();
        Globals::time_interval_1_ms_ = config["timing_method"]["time_interval_1_ms"].asInt();
        Globals::time_interval_stop_ms_ = config["timing_method"]["time_interval_stop_ms"].asInt();
        Globals::number_of_repeat_ = config["number_of_repeat"].asInt();
        Globals::original_message_ = config["message_to_send"].asString();
        Globals::results_path = config["results_path"].asString();
    }
}
