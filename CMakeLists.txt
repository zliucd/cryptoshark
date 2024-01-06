cmake_minimum_required(VERSION 3.18)
project(cryptoshark)

set(CMAKE_CXX_STANDARD 11)

set(TARGET_NAME main)

include_directories(include)
include_directories(tests)

add_executable(${TARGET_NAME}
                include/aes.h
                include/md5.h
                include/sha1.h
                include/sha256.h
                include/sm3.h
                include/sm4.h
                include/util.h
                src/aes.cpp
                src/md5.cpp
                src/sha1.cpp
                src/sha256.cpp
                src/sm3.cpp
                src/sm4.cpp
                src/util.cpp
                tests/test_aes.hpp
                tests/test_hash.hpp
                tests/test_sm4.hpp
                tests/test_util.hpp
                program/main.cpp)

target_link_libraries(${TARGET_NAME})