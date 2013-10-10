set(_sources test_safenet.cpp)

set(GTEST_INCLUDE_DIR /usr/include/gtest)
set(GTEST_LIBRARY /usr/lib/libgtest.a)
set(GTEST_LIBRARY_DEBUG ${GTEST_LIBRARY})

set(CMAKE_CXX_FLAGS "-g -Wall")

# Setup testing
enable_testing()
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIR})

# Add test cpp file
add_executable(runUnitTests
    test_safenet.cpp
)

# Link test executable against gtest & gtest_main
target_link_libraries(runUnitTests ${GTEST_LIBRARY_DEBUG} pthread )

add_test(
    NAME runUnitTests
    COMMAND runUnitTests
)
