cmake_minimum_required(VERSION 3.13)

project(encrypted_covert_channel)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(TINS_LIBRARY tins)
include(FindPCAP.cmake)
add_executable(encrypted_covert_channel main.cpp include/Globals.h src/AES.hpp include/Receiver.h
        src/Receiver.cpp src/Sender.cpp include/Cryptographer.h src/Cryptographer.cpp
        include/Sender.h include/RSA.h src/RSA.cpp
        src/Globals.cpp include/Grain.h src/Grain.c
        src/Evaluation.cpp include/Evaluation.h include/DES.h src/DES.cpp src/Clefia.cpp include/Clefia.h)

target_link_libraries(encrypted_covert_channel ${PCAP_LIBRARY})
target_link_libraries(encrypted_covert_channel "${TINS_LIBRARY}")
target_link_libraries(encrypted_covert_channel libpthread.so.0)


find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
link_libraries(${JSONCPP_LIBRARIES})
target_link_libraries(encrypted_covert_channel ${JSONCPP_LIBRARIES})

find_package(OpenSSL REQUIRED)
target_link_libraries(encrypted_covert_channel OpenSSL::SSL)
