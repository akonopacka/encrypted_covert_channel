#ifndef ENCRYPTED_COVERT_CHANNEL_GLOBALS_H
#define ENCRYPTED_COVERT_CHANNEL_GLOBALS_H

#include <chrono>
#include <string>
#include <jsoncpp/json/json.h>
#include <jsoncpp/json/value.h>

using std::string;
namespace Globals {
    extern std::string covert_channel_type_;
    extern std::chrono::high_resolution_clock::time_point time_of_last_packet_;
    extern std::chrono::high_resolution_clock::time_point time_received_;
    extern std::chrono::high_resolution_clock::time_point start_receiving, stop_receiving;
    extern std::chrono::duration<double, std::milli> time_span_;
    extern long last_packet_timestamp_;
    extern int last_seq_;
    extern int timing_counter;
    extern std::string message_;
    extern std::string original_message_;
    extern std::string results_path;
    extern std::string interface_;
    extern std::string IPv4_address;
    extern std::string IPv6_address;
    extern int number_of_repeat_;
    extern int src_port_;
    extern int dst_port_;
    extern int time_interval_1_ms_;
    extern int time_interval_stop_ms_;
    extern bool is_started_receiving;
    extern bool is_encrypted;
    extern std::string cipher_type_;
    extern std::string channel_message;

    extern void load_globals(Json::Value config);

}

#endif //ENCRYPTED_COVERT_CHANNEL_GLOBALS_H
