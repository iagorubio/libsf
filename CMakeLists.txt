cmake_minimum_required(VERSION 3.1)

project(libsf LANGUAGES C)

file(GLOB_RECURSE SRCS "src/*.c")

set(sources ${SRCS})

# execute_process(COMMAND libnet-config --defines OUTPUT_VARIABLE LIBNET_DEFINES)
# execute_process(COMMAND libnet-config --libs OUTPUT_VARIABLE LIBNET_LIBS)

add_executable(libsf_import import/libsf_import.c)
target_link_libraries(libsf_import PUBLIC sf db)

add_executable(ledgermain sample/legerdemain.c)

add_library(sf STATIC ${sources})

target_include_directories(ledgermain PUBLIC include)

target_link_libraries(ledgermain PUBLIC sf pcap net db)



