cmake_minimum_required(VERSION 3.20.0) 

project(simplesrp DESCRIPTION "SRP 6a implementation in C++ compatible with Apple")

if (NOT WIN32)
    add_compile_options(-std=c++17)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        add_compile_options(-stdlib=libc++)
    endif()
endif()

if (APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15")
endif()

OPTION(SIMPLESRP_TESTING_ENABLE "Build simplesrp unit-tests." OFF)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})


### simplesrp library ###

set(LIB_SOURCES
    include/simplesrp/simplesrp.h
    include/simplesrp/routines.h
    include/simplesrp/details.h
    include/simplesrp/bn.h

    src/srp.cpp
    src/routines.cpp
    src/bn.cpp
)

add_library(simplesrp STATIC ${LIB_SOURCES})
target_include_directories(simplesrp PUBLIC "include")


### simplesrp unit-tests ###

if (SIMPLESRP_TESTING_ENABLE)
    set(TEST_SOURCES
        tests/SRPTests.cpp
    )
    add_executable(simplesrp_tests ${TEST_SOURCES})
    target_link_libraries(simplesrp_tests simplesrp)
    
    # OpenSSL
    target_link_libraries(simplesrp_tests OpenSSL::Crypto)
        
    # GoogleTest
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    FetchContent_MakeAvailable(googletest)
        
    target_include_directories(simplesrp_tests PRIVATE ${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    target_include_directories(simplesrp_tests PRIVATE ${gmock_SOURCE_DIR}/include ${gmock_SOURCE_DIR})
    target_link_libraries(simplesrp_tests gtest gmock gtest_main)
endif()
