//
// Created by root on 02/11/2020.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_GLOBALS_H
#define ENCRYPTED_COVERT_CHANNEL_GLOBALS_H

#include <chrono>
#include <string>

using std::string;
namespace Globals
{
    extern std::chrono::high_resolution_clock::time_point time_of_last_packet_;
    extern std::chrono::high_resolution_clock::time_point time_received_;
    extern std::chrono::duration<double, std::milli> time_span_;
    extern double last_packet_timestamp_;
    extern int last_seq_;
    extern std::string message_;
    extern std::string interface_;
    extern std::string IPv4_address;
    extern int src_port_;
    extern int dst_port_;
    extern int time_interval_1_ms_;
    extern int time_interval_stop_ms_;
    extern bool is_encrypted;
    extern std::string cipher_type;

}

#endif //ENCRYPTED_COVERT_CHANNEL_GLOBALS_H
