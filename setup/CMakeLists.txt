set(CMAKE_CXX_FLAGS "-g -Wall")

find_package(Cryptoki REQUIRED)

set(Cryptoki_Include "/opt/ETcpsdk/include")
include_directories(${Cryptoki_Include})

add_executable(setup
    main.cpp
)

target_link_libraries(setup         pthread 
                                    Safenet 
                                    cryptoki
                                    ctutil
                                    util
                                    log4cxx
                                    )
