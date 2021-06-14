//
// Created by root on 14.06.2021.
//


#include <fstream>
#include "../include/Evaluation.h"


Evaluation::Evaluation() {
}

float Evaluation::get_CPU_value() {
    std::ifstream input;
    input.open("/proc/stat", std::ios_base::in);
    int total_diff = 0;
    float percent = 0;
    if (input.is_open()) {
        std::string cpu;
        int user, nice, system, idle, iowait, irq, softirq, stealstolen, guest;
        input >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> stealstolen >> guest;
        input.close();
        int total_cpu_time = user + nice + system + idle + irq + softirq + guest + iowait + stealstolen;
        if (this->total_cpu_time != 0) {
            total_diff = total_cpu_time - this->total_cpu_time;
            int idle_diff = idle - this->total_idle_time;
            int user_diff = user - this->total_user_time;
            int sys_diff = system - this->total_sys_time;
            float total_rate = (total_diff - idle_diff) * 1.0 / total_diff;
            float idle_rate = idle_diff * 1.0 / total_diff;
            float user_rate = user_diff * 1.0 / total_diff;
            float sys_rate = sys_diff * 1.0 / total_diff;
            percent  = user_rate;

            std::cout<<"CPU usage: total_rate: " << total_rate << " idle_rate: "<<idle_rate<< " user_rate: "<<user_rate<< " sys_rate: "<<sys_rate<< "\n";

        }
        this->total_cpu_time = total_cpu_time;
        this->total_idle_time = idle;
        this->total_sys_time = system;
        this->total_user_time = user;
    }

//    percent = 0.7;
    return percent;
}

float Evaluation::get_mem_value() {
    std::ifstream input;
    input.open("/proc/meminfo", std::ios_base::in);
    float rate_ = 0;
    if (input.is_open()) {
        int mem_total, mem_free, mem_used, mem_cached;
        int swap_total, swap_free, swap_used;
        std::string tmp;
        char buffer[100];
        int values[45];
        int i = 0;
        while (i < 45) {
            input >> tmp >> values[i];
            input.getline(buffer, 100);
            i++;
        }
        mem_total = values[0];
        mem_free = values[1];
        mem_used = mem_total - mem_free;
        mem_cached = values[4];
        swap_total = values[14];
        swap_free = values[15];
        swap_used = swap_total - swap_free;
        float rate = mem_used * 100.0 / mem_total;
        std::cout<<"Memory usage: mem_total: " << mem_total << " mem_used: "<<mem_used<< " rate: "<<rate<< "\n";
        rate_ = rate;
        input.close();
    }
    return rate_;
}

