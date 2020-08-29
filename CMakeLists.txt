cmake_minimum_required(VERSION 3.17)
project(encrypted_covert_channel)

set(CMAKE_CXX_STANDARD 14)

add_executable(encrypted_covert_channel main.cpp TCP_Packet.cpp TCP_Packet.h)