cmake_minimum_required(VERSION 2.8.7)
option(test "Build all tests" OFF) 
project(SafenetHelper)

set(SafenetHelper 1)
set(SafenetHelper 0)


add_subdirectory(src)

add_subdirectory(test)
