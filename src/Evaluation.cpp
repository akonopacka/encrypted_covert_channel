//
// Created by root on 14.06.2021.
//


#include <fstream>
#include <map>
#include <cmath>
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
            percent = user_rate;

            std::cout << "CPU usage: total_rate: " << total_rate << " idle_rate: " << idle_rate << " user_rate: "
                      << user_rate << " sys_rate: " << sys_rate << "\n";

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
        std::cout << "Memory usage: mem_total: " << mem_total << " mem_used: " << mem_used << " rate: " << rate << "\n";
        rate_ = rate;
        input.close();
    }
    return rate_;
}

// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
std::string Evaluation::currentDateTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d_%X", &tstruct);
    return buf;
}

void Evaluation::save_results_to_file(std::string results, std::string path, std::string method, std::string mode) {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d_%X", &tstruct);
    std::string currentDateTime = buf;
    //Generate the name of filed
    std::string filename =
            mode + "_" + Globals::covert_channel_type_ + "_" + Globals::cipher_type_ + "_" + currentDateTime + ".txt";
    path = path + filename;
    //Save results to file
    std::cout << "Saving results to file in path: " << path << std::endl << std::endl;
    std::ofstream myfile;
    myfile.open(path);
    myfile << results;
    myfile.close();
    std::cout << results << std::endl;
}

float Evaluation::get_BER(std::string original_message, std::string received_message) {
    int length = std::max(received_message.length(), original_message.length());
    int counter = 0;
    for (int i = 0; i < length; i++) {
        if (received_message[i] != original_message[i]) {
            counter++;
        }
    }
    float ber = 0;
    if (length > 0) {
        ber = float(counter) / length;
    }
    return ber;
}

float Evaluation::get_CPU_value_of_process() {
    static clock_t lastCPU, lastSysCPU, lastUserCPU;
    static int numProcessors;
    FILE *file;
    struct tms timeSample;
    char line[128];

    lastCPU = times(&timeSample);
    lastSysCPU = timeSample.tms_stime;
    lastUserCPU = timeSample.tms_utime;

    file = fopen("/proc/cpuinfo", "r");
    numProcessors = 0;
    while (fgets(line, 128, file) != NULL) {
        if (strncmp(line, "processor", 9) == 0) numProcessors++;
    }
    fclose(file);
    clock_t now;
    double percent;

    now = times(&timeSample);
    if (now <= lastCPU || timeSample.tms_stime < lastSysCPU ||
        timeSample.tms_utime < lastUserCPU) {
        //Overflow detection. Just skip this value.
        percent = -1.0;
    } else {
        percent = (timeSample.tms_stime - lastSysCPU) +
                  (timeSample.tms_utime - lastUserCPU);
        percent /= (now - lastCPU);
        percent /= numProcessors;
        percent *= 100;
    }
    lastCPU = now;
    lastSysCPU = timeSample.tms_stime;
    lastUserCPU = timeSample.tms_utime;
    return percent;
}

float Evaluation::calculate_entropy(std::string message) {
    int elements = message.length();
    float entropy = 0;
    std::map<char, long> counts;
    typename std::map<char, long>::iterator it;
    for (int dataIndex = 0; dataIndex < elements; ++dataIndex) {
        const char letter = message[dataIndex];
        const auto it = counts.find(letter);

        if (it == counts.end()) {
            counts.insert(std::make_pair(letter, 1));
        } else {
            int prev_value = it->second;
            prev_value++;
            it->second = prev_value;
        }
    }
    it = counts.begin();
    while (it != counts.end()) {
        float p_x = (float) it->second / elements;
        if (p_x > 0) entropy -= p_x * log(p_x) / log(2);
        it++;
    }
    return entropy;
}

int Evaluation::get_levenshtein_distance(std::string original_message, std::string received_message) {
    const std::size_t len1 = original_message.size(), len2 = received_message.size();
    std::vector<std::vector<unsigned int>> d(len1 + 1, std::vector<unsigned int>(len2 + 1));

    d[0][0] = 0;
    for(unsigned int i = 1; i <= len1; ++i) d[i][0] = i;
    for(unsigned int i = 1; i <= len2; ++i) d[0][i] = i;

    for(unsigned int i = 1; i <= len1; ++i)
        for(unsigned int j = 1; j <= len2; ++j)
            // note that std::min({arg1, arg2, arg3}) works only in C++11,
            // for C++98 use std::min(std::min(arg1, arg2), arg3)
            d[i][j] = std::min({ d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (original_message[i - 1] == received_message[j - 1] ? 0 : 1) });
    return d[len1][len2];
}

