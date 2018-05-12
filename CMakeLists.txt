cmake_minimum_required(VERSION 3.5)

project(scapenet-khg)

add_compile_options(-W -Wall)

# set library
set(LIB_FILES
	src/network_scan.c
	src/node_kill.c
)

add_library(scapnet
	SHARED
	${LIB_FILES}
)

target_include_directories(scapnet
	PUBLIC
	${PROJECT_SOURCE_DIR}/include
)

# set binary
set(SRC_FILES
	src/main.c
)

add_executable(scan ${SRC_FILES})

target_include_directories(scan
	PUBLIC
	${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(scan
	PUBLIC
	scapnet
	-lpthread -lpcap
)
