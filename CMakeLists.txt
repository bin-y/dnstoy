cmake_minimum_required(VERSION 3.1.0)
project (dnstoy)

set(BOOST_ROOT "./libs/boost-1.69.0-install")
set(Boost_USE_STATIC_LIBS ON)
find_package( Boost 1.69 COMPONENTS program_options system log REQUIRED )
include_directories (SYSTEM ${Boost_INCLUDE_DIR})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++17")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

# Get version from version.h
file(READ src/version.h version_h)
if (NOT version_h MATCHES "DNSTOY_VERSION ([0-9]+)([0-9][0-9])([0-9][0-9])")
  message(FATAL_ERROR "Cannot get DNSTOY_VERSION from version.h.")
endif ()

# Use math to skip leading zeros if any.
math(EXPR CPACK_PACKAGE_VERSION_MAJOR ${CMAKE_MATCH_1})
math(EXPR CPACK_PACKAGE_VERSION_MINOR ${CMAKE_MATCH_2})
math(EXPR CPACK_PACKAGE_VERSION_PATCH ${CMAKE_MATCH_3})
 
include_directories("${PROJECT_BINARY_DIR}")
 
# add the executable
add_executable(dnstoy 
  src/main.cc src/configuration.cc src/engine.cc src/server.cc src/logging.cc
  src/proxy_context.cc src/proxy_remote.cc
  src/query.cc src/tls_resolver.cc
  src/dns_message_decoder.cc src/dns_message_encoder.cc
)
target_link_libraries( dnstoy ${Boost_LIBRARIES} pthread ssl crypto )