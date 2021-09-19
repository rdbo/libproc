cmake_minimum_required(VERSION 3.0)

project(libproc C)

option(BUILD_STATIC "Build static library" OFF)
option(BUILD_TESTS "Build tests" ON)
option(DEBUG OFF)

set(LIBPROC_DIR "${PROJECT_SOURCE_DIR}/libproc")
set(LIBPROC_SRC "${LIBPROC_DIR}/libproc.c")

if(DEBUG)
	add_compile_options(-g -Wall -Wextra)
endif()

if(BUILD_STATIC)
	add_library(libproc STATIC ${LIBPROC_SRC})
else()
	add_library(libproc SHARED ${LIBPROC_SRC})
endif()
set_target_properties(libproc PROPERTIES PREFIX "")

if(BUILD_TESTS)
	set(TESTS_DIR "${PROJECT_SOURCE_DIR}/tests")
	set(TESTS_SRC "${TESTS_DIR}/tests.c")
	add_executable(tests ${TESTS_SRC})
	target_include_directories(tests PUBLIC ${LIBPROC_DIR})
	target_link_libraries(tests libproc)
endif()
