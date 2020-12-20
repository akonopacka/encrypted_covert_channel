cmake_minimum_required(VERSION 3.13)

project(encrypted_covert_channel)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(TINS_LIBRARY tins)
include(FindPCAP.cmake)
include(FetchContent)
FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/whoshuu/cpr.git GIT_TAG c8d33915dbd88ad6c92b258869b03aba06587ff9) # the commit hash for 1.5.0
FetchContent_MakeAvailable(cpr)
add_executable(encrypted_covert_channel main.cpp include/Globals.h   TCP_Packet.cpp TCP_Packet.h include/Receiver.h src/Receiver.cpp   src/Sender.cpp include/Sender.h src/Cryptographer.cpp include/Cryptographer.h src/MethodTypeEnum.cpp src/Globals.cpp)
target_link_libraries(encrypted_covert_channel ${PCAP_LIBRARY})
target_link_libraries(encrypted_covert_channel "${TINS_LIBRARY}")
target_link_libraries(encrypted_covert_channel cpr::cpr)

find_package(OpenSSL REQUIRED)
target_link_libraries(encrypted_covert_channel OpenSSL::SSL)
