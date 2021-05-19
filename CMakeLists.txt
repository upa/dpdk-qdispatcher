cmake_minimum_required(VERSION 3.10)

project(qdispatcher C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK libdpdk REQUIRED)

set(CMAKE_C_FLAGS "-Wall -g")

# qdispatcher
add_executable(dpdk-qdispatcher	src/qdispatcher.c)
target_include_directories(dpdk-qdispatcher PUBLIC
				./src
				${LIBDPDK_INCLUDE_DIRS}
				)
target_link_libraries(dpdk-qdispatcher ${LIBDPDK_LIBRARIES})
target_compile_options(dpdk-qdispatcher PRIVATE ${LIBDPDK_CFLAGS_OTHER})

# libqdc
add_library(qdc STATIC src/qdc.c)
set_property(TARGET qdc PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(qdc PUBLIC
				./src
				${LIBDPDK_INCLUDE_DIRS}
				)
target_link_libraries(qdc ${LIBDPDK_LIBRARIES})
target_compile_options(qdc PRIVATE ${LIBDPDK_CFLAGS_OTHER})

add_subdirectory(./test)
