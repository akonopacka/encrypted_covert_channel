//
// Created by root on 02/11/2020.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_GLOBALS_H
#define ENCRYPTED_COVERT_CHANNEL_GLOBALS_H

#include <chrono>
#include <string>
using std::string;

extern std::chrono::high_resolution_clock::time_point time_of_last_packet_;
extern std::chrono::high_resolution_clock::time_point time_received_;
extern std::chrono::duration<double, std::milli> time_span_;
extern double last_packet_timestamp_;
extern std::string message_;


#endif //ENCRYPTED_COVERT_CHANNEL_GLOBALS_H
