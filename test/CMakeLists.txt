cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_FLAGS "-Wall -g")

add_executable(test-join-leave ./join-leave.c) 
target_include_directories(test-join-leave PRIVATE
				../src
				${LIBDPDK_INCLUDE_DIRS}
				)
target_link_libraries(test-join-leave qdc ${LIBDPDK_LIBRARIES})
target_compile_options(test-join-leave PRIVATE ${LIBDPDK_CFLAGS_OTHER})
