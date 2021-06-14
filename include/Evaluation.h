//
// Created by root on 14.06.2021.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_EVALUATION_H
#define ENCRYPTED_COVERT_CHANNEL_EVALUATION_H
//#include "CPUSnapshot.h"

#include <chrono>
#include <thread>
#include <iostream>

class Evaluation {
public:
    int total_cpu_time;
    int total_user_time;
    int total_sys_time;
    int total_idle_time;
    float encrypting_time, sending_time;

    Evaluation();
    float get_CPU_value();
    float get_mem_value();

};


#endif //ENCRYPTED_COVERT_CHANNEL_EVALUATION_H
