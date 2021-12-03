#ifndef ENCRYPTED_COVERT_CHANNEL_EVALUATION_H
#define ENCRYPTED_COVERT_CHANNEL_EVALUATION_H

#include <chrono>
#include <thread>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include "sys/times.h"
#include "sys/vtimes.h"
#include "Globals.h"

class Evaluation {
public:
    int total_cpu_time;
    int total_user_time;
    int total_sys_time;
    int total_idle_time;

    Evaluation();

    float get_CPU_value();

    float get_CPU_value_of_process();

    float get_mem_value();

    static void save_results_to_file(std::string results, std::string path, std::string method, std::string mode);

    std::string currentDateTime();

    static float get_BER(std::string original_message, std::string received_message);

    static float calculate_entropy(std::string message);
};


#endif //ENCRYPTED_COVERT_CHANNEL_EVALUATION_H
