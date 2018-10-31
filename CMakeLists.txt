cmake_minimum_required(VERSION 3.5)

project(scapenet-khg)

add_compile_options(-W -Wall)

# set library
set(LIB_FILES
	src/network_scan.c
	src/node_kill.c
)

add_library(scapenet
	SHARED
	${LIB_FILES}
)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}")
set_target_properties(scapenet PROPERTIES VERSION ${VERSION})

target_include_directories(scapenet
	PUBLIC
	${PROJECT_SOURCE_DIR}/include
)

# set binary
set(SRC_FILES
	src/main.c
)

add_executable(scan ${SRC_FILES})

include(cmake/FindPCAP.cmake)

target_include_directories(scan
	PUBLIC
	${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(scan
	PUBLIC
	scapenet
	-lpthread ${PCAP_LIBRARY}
)
