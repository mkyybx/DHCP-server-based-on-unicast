cmake_minimum_required(VERSION 3.7)
project(untitled1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-lpthread")

set(SOURCE_FILES dhcp_server.cpp)
add_executable(untitled1 ${SOURCE_FILES})