cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_FLAGS "-Wall -g")

set(INCLUDE_DIRS ../src ${LIBDPDK_INCLUDE_DIRS})
set(targets join-leave xmit)

foreach(target IN LISTS targets)
	add_executable(test-${target} ./${target}.c)
	target_include_directories(test-${target} PRIVATE ${INCLUDE_DIRS})
	target_link_libraries(test-${target} qdc ${LIBDPDK_LIBRARIES})
	target_compile_options(test-${target} PRIVATE ${LIBDPDK_CFLAGS_OTHER})
endforeach()
