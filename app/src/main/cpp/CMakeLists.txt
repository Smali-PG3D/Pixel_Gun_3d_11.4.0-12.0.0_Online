cmake_minimum_required (VERSION 3.10.2)
project(native-lib)

enable_language(CXX)
enable_language(ASM)

set(SOURCE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(KITTYMEMORY_PATH ${CMAKE_CURRENT_SOURCE_DIR}/KittyMemory)
file(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)
set(KEYSTONE_LIB ${KITTYMEMORY_PATH}/Deps/Keystone/libs-android/${CMAKE_ANDROID_ARCH_ABI}/libkeystone.a)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument -O0 -g -std=c++20 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument -O2 -s -std=c++20 -DNDEBUG")

add_library(${PROJECT_NAME}
        SHARED
        ${KITTYMEMORY_SRC}
        )

target_include_directories(${PROJECT_NAME}
        PRIVATE
        ${SOURCE_PATH}
        )

target_sources(${PROJECT_NAME}
        PRIVATE

        main.cpp
        )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Dobby/include)

set_target_properties(${PROJECT_NAME}
        PROPERTIES

        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS YES
        )

target_compile_features(${PROJECT_NAME}
        INTERFACE

        cxx_std_17
        )

message(STATUS "CMAKE_BUILD_TYPE is ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BUILD_TYPE_COMPILER_FLAGS
            -g3
            )
    set(BUILD_TYPE_LINKER_FLAGS
            )
else()
    set(BUILD_TYPE_COMPILER_FLAGS
            -fvisibility=hidden
            -fvisibility-inlines-hidden
            -fomit-frame-pointer
            -ffunction-sections
            -fdata-sections
            -g0
            -Ofast
            -DNDEBUG
            )
    set(BUILD_TYPE_LINKER_FLAGS
            -Wl
            --strip-all
            )
endif()
target_compile_options(${PROJECT_NAME}
        INTERFACE

        -Wno-error=format-security
        -fpermissive
        -fno-rtti
        -fno-exceptions
        ${BUILD_TYPE_COMPILER_FLAGS}
        )

set_property(TARGET ${PROJECT_NAME}
        APPEND

        PROPERTY LINK_FLAGS

        ${BUILD_TYPE_LINKER_FLAGS}
        )
# Requires cmake >= 3.13
#target_link_options(${PROJECT_NAME}
#    INTERFACE
#
#    ${BUILD_TYPE_LINKER_FLAGS}
#)

find_library(
        log-lib

        log
)

set(DOBBY_LIB ${CMAKE_CURRENT_SOURCE_DIR}/Dobby/${CMAKE_ANDROID_ARCH_ABI}/libdobby.a)

target_link_libraries(${PROJECT_NAME}
        ${log-lib}
        ${DOBBY_LIB}
        -llog ${KEYSTONE_LIB}
        )
