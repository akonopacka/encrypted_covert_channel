//
// Created by root on 20/12/2020.
//
#include <chrono>
#include <string>
#include "../include/Globals.h"

using std::string;
namespace Globals
{
    std::chrono::high_resolution_clock::time_point time_of_last_packet_ = std::chrono::high_resolution_clock::now();
    std::chrono::high_resolution_clock::time_point time_received_= std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> time_span_= Globals::time_received_ - Globals::time_of_last_packet_;
    std::chrono::high_resolution_clock::time_point start_receiving = std::chrono::high_resolution_clock::now();
    std::chrono::high_resolution_clock::time_point stop_receiving = std::chrono::high_resolution_clock::now();
    double last_packet_timestamp_ = 0;
    int last_seq_ = 0;
    std::string message_ = "";
    std::string interface_ = "lo";
    std::string IPv4_address = "127.0.0.1";
    int src_port_ = 1111;
    int dst_port_= 1111;
    int time_interval_1_ms_ = 1100;
    int time_interval_stop_ms_ = 6000;
    bool is_encrypted = false;
    std::string cipher_type = "aes";
}
