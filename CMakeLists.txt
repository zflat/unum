cmake_minimum_required(VERSION 3.7 FATAL_ERROR)
project(unum LANGUAGES CXX C)

set(VERSION "0.1.0")
set(VERSION_MAJOR 0)
string(TIMESTAMP BUILD_TIME UTC)

SET(CMAKE_CXX_STANDARD 11)
SET(BUILD_SHARED_LIBRARIES OFF)
SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
SET(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

##############
# Dependencies
#
find_library(SOCI_LIBRARY soci_core HINTS "/usr/local/lib64")
find_library(SOCI_SQLITE3_LIBRARY soci_sqlite3 HINTS "/usr/local/lib64")
find_library(SOCI_MYSQL_LIBRARY soci_mysql HINTS "/usr/local/lib64")
find_library(MYSQL_CLIENT_LIBRARY mysqlclient HINTS "/usr/lib/x86_64-linux-gnu/")
# find_library(FCGI_LIBRARY NAMES fcgi++ fcgi HINTS "/usr/lib")

message(STATUS "using ${SOCI_LIBRARY}")
message(STATUS "using ${SOCI_SQLITE3_LIBRARY}")
message(STATUS "using ${SOCI_MYSQL_LIBRARY}")
message(STATUS "using ${MYSQL_CLIENT_LIBRARY}")
# message(STATUS "found ${FCGI_LIBRARY}")

add_library(mysqlclient STATIC IMPORTED GLOBAL)
add_library(soci_mysql STATIC IMPORTED GLOBAL)
add_library(soci_sqlite3 STATIC IMPORTED GLOBAL)
add_library(soci_core STATIC IMPORTED GLOBAL)

set_target_properties(mysqlclient PROPERTIES IMPORTED_LOCATION ${MYSQL_CLIENT_LIBRARY})
set_target_properties(soci_mysql PROPERTIES IMPORTED_LOCATION ${SOCI_MYSQL_LIBRARY})
set_target_properties(soci_sqlite3 PROPERTIES IMPORTED_LOCATION ${SOCI_SQLITE3_LIBRARY})
set_target_properties(soci_core PROPERTIES IMPORTED_LOCATION ${SOCI_LIBRARY})

# Helpful comments: https://stackoverflow.com/a/36922782
set_target_properties(mysqlclient PROPERTIES IMPORTED_LINK_INTERFACE_LIBRARIES pthread)
set_target_properties(soci_core PROPERTIES IMPORTED_LINK_INTERFACE_LIBRARIES pthread)
set_target_properties(soci_core PROPERTIES IMPORTED_LINK_INTERFACE_LIBRARIES dl)
set_target_properties(soci_sqlite3 PROPERTIES IMPORTED_LINK_INTERFACE_LIBRARIES soci_core)

include_directories("/usr/include/mysql")

#########################
# Header and source files
#
include_directories(
  "${CMAKE_CURRENT_BINARY_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/include/core ${CONFIG_INCLUDE_DIR})

# Vendored dependencies
include_directories(${CMAKE_SOURCE_DIR}/vendor/botan/include )
include_directories(${CMAKE_SOURCE_DIR}/vendor/jsoncpp/include )
include_directories(${CMAKE_SOURCE_DIR}/vendor/spdlog/include )

file(GLOB VENDOR_SRC_FILES_JSONCPP ${CMAKE_SOURCE_DIR}/vendor/jsoncpp/src/*.cpp)
# botan amalgamated
# ./configure.py --amalgamation --single-amalgamation-file --minimized-build --enable-modules=system_rng,sha2_32,hotp,srp6
file(GLOB VENDOR_SRC_FILES_BOTAN ${CMAKE_SOURCE_DIR}/vendor/botan/src/*.cpp)
set(SRC_FILES_VENDOR)
list(APPEND SRC_FILES_VENDOR ${VENDOR_SRC_FILES_BOTAN} ${VENDOR_SRC_FILES_JSONCPP})

# Project files
file(GLOB SRC_FILES_CORE ${CMAKE_SOURCE_DIR}/src/core/*.cpp)
set(SRC_FILES_APP)
file(GLOB SRC_FILES_CONTROLLERS ${CMAKE_SOURCE_DIR}/src/controllers/*.cpp)
file(GLOB SRC_FILES_MODELS ${CMAKE_SOURCE_DIR}/src/models/*.cpp)
file(GLOB SRC_FILES_VIEWS ${CMAKE_SOURCE_DIR}/src/views/*.cpp)
list(APPEND SRC_FILES_APP ${SRC_FILES_CONTROLLERS} ${SRC_FILES_MODELS} ${SRC_FILES_VIEWS})

# Combined list of sorce files
set(SRC_FILES)
list(APPEND SRC_FILES ${SRC_FILES_VENDOR} ${SRC_FILES_CORE} ${SRC_FILES_APP})

#############
# Executables

add_executable(app.fcgi src/main.cpp ${SRC_FILES})
target_link_libraries(app.fcgi soci_core soci_mysql mysqlclient soci_sqlite3 sqlite3 fcgi++ fcgi pthread curl z)

#########
# Testing
#
enable_testing()
add_subdirectory(tests)

