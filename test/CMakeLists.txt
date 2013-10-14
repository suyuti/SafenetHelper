# Mehmet Suyuti Dindar
# 11.10.2013 
# SmartSoft

set(_sources test_safenet.cpp)

set(GTEST_INCLUDE_DIR /usr/include/gtest)
set(GTEST_LIBRARY /usr/lib/libgtest.a)
set(GTEST_LIBRARY_DEBUG ${GTEST_LIBRARY})

set(CMAKE_CXX_FLAGS "-g -Wall")

# Setup testing
enable_testing()
find_package(GTest REQUIRED)
find_package(Cryptoki REQUIRED)
include_directories(${GTEST_INCLUDE_DIR})

set(Cryptoki_Include "/opt/ETcpsdk/include")
include_directories(${Cryptoki_Include})


add_executable(runUnitTests
    test_safenet.cpp
)

target_link_libraries(runUnitTests  ${GTEST_LIBRARY_DEBUG} 
                                    pthread 
                                    Safenet 
                                    cryptoki
                                    ctutil
                                    util
                                    )

add_test(
    NAME    runUnitTests
    COMMAND runUnitTests
)
