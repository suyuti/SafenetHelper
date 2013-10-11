# Mehmet Suyuti Dindar
# 11.10.2013 
# SmartSoft

set(cryptokiSources     cryptokiHelper/CryptokiHelper.cpp
                        cryptokiHelper/ExceptionCryptoki.cpp
                        cryptokiHelper/Key.cpp)

set(utilSources         util/Buffer.cpp
                        util/logger.cpp)

set(libSafenet_sources  SafenetHelper.cpp 
                        SafenetHelperImpl.cpp
                        ${utilSources}
                        ${cryptokiSources})

set(Cryptoki_Include "/opt/ETcpsdk/include")

include_directories(${Cryptoki_Include})

add_library(Safenet ${libSafenet_sources})