cmake_minimum_required(VERSION 3.13)

project(encrypted_covert_channel)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(TINS_LIBRARY tins)
include(FindPCAP.cmake)

add_executable(encrypted_covert_channel main.cpp TCP_Packet.cpp TCP_Packet.h src/Receiver.cpp include/Receiver.h include/Globals.h src/Sender.cpp include/Sender.h src/Cryptographer.cpp include/Cryptographer.h)
target_link_libraries(encrypted_covert_channel ${PCAP_LIBRARY})
target_link_libraries(encrypted_covert_channel "${TINS_LIBRARY}")

find_package(OpenSSL REQUIRED)
target_link_libraries(encrypted_covert_channel OpenSSL::SSL)
