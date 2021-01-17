cmake_minimum_required(VERSION 3.13)

project(encrypted_covert_channel)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(TINS_LIBRARY tins)
include(FindPCAP.cmake)
add_executable(encrypted_covert_channel src/des.hpp src/Cryptographer.cpp include/Cryptographer.h main.cpp include/Globals.h src/aes.hpp include/Receiver.h src/Receiver.cpp
        src/Sender.cpp include/Sender.h  src/MethodTypeEnum.cpp
        src/Globals.cpp clefia/clefia.h clefia/clefia.c src/present.hpp)

target_link_libraries(encrypted_covert_channel ${PCAP_LIBRARY})
target_link_libraries(encrypted_covert_channel "${TINS_LIBRARY}")

find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
link_libraries(${JSONCPP_LIBRARIES})
target_link_libraries(encrypted_covert_channel ${JSONCPP_LIBRARIES})

