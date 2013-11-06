# Mehmet Suyuti Dindar
# 11.10.2013 
# SmartSoft

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)

project(SafenetHelper)

add_subdirectory(test)
add_subdirectory(src)
add_subdirectory(setup)


