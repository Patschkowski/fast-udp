cmake_minimum_required(VERSION 3.28)

project(fast_udp CXX)

find_package(Microsoft.GSL CONFIG REQUIRED)

add_executable(fast_udp main.cpp)
target_compile_features(fast_udp PRIVATE cxx_std_23)
target_link_libraries(fast_udp PRIVATE Microsoft.GSL::GSL ws2_32)