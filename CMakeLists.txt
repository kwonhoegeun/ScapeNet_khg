cmake_minimum_required(VERSION 2.8)

project(scapenet-khg)

set(OUTPUT_FILE "scan")
set(SRC_FILES
	main.c
	network_scan.c
	node_kill.c
)

ADD_COMPILE_OPTIONS(-W -Wall)
add_executable(${OUTPUT_FILE} ${SRC_FILES})

target_link_libraries(${OUTPUT_FILE} -lpthread)
target_link_libraries(${OUTPUT_FILE} -lpcap)
