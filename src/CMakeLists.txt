# Mehmet Suyuti Dindar
# 11.10.2013 
# SmartSoft

set(cryptokiSources     cryptokiHelper/CryptokiHelper.cpp
                        cryptokiHelper/ExceptionCryptoki.cpp
                        cryptokiHelper/Key.cpp
                        cryptokiHelper/DataObject.cpp
                        )

set(utilSources         util/Buffer.cpp
                        util/logger.cpp)

set(libSources          SafenetHelper.cpp
                        SafenetHelperImpl.cpp)

set(libSafenet_sources  
                        #${libSources}
                        ${utilSources}
                        ${cryptokiSources})

set(Cryptoki_Include "/opt/ETcpsdk/include")

include_directories(${Cryptoki_Include})

add_library(Safenet ${libSafenet_sources})