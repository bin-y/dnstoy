cmake_minimum_required(VERSION 3.1.0)
project (dnstoy)

set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/libs/boost-1.70.0-install")
set(Boost_USE_STATIC_LIBS ON)
find_package( Boost 1.70 COMPONENTS program_options system log REQUIRED )
include_directories (SYSTEM ${Boost_INCLUDE_DIR})

set(CMAKE_CXX_STANDARD 17)

# Get version from version.h
file(READ src/version.h version_h)
if (NOT version_h MATCHES "DNSTOY_VERSION ([0-9]+)([0-9][0-9])([0-9][0-9])")
  message(FATAL_ERROR "Cannot get DNSTOY_VERSION from version.h.")
endif ()

# Use math to skip leading zeros if any.
math(EXPR CPACK_PACKAGE_VERSION_MAJOR ${CMAKE_MATCH_1})
math(EXPR CPACK_PACKAGE_VERSION_MINOR ${CMAKE_MATCH_2})
math(EXPR CPACK_PACKAGE_VERSION_PATCH ${CMAKE_MATCH_3})
 
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
 
# add the executable
add_executable(dnstoy 
  src/main.cpp src/configuration.cpp src/engine.cpp src/server.cpp src/logging.cpp
  src/performance_record.cpp
  src/proxy_context.cpp
  src/query.cpp src/resolver.cpp src/tls_resolver.cpp
  src/dns_message_decoder.cpp src/dns_message_encoder.cpp
)

if(MSVC)
  target_compile_options(dnstoy PRIVATE /W4 /WX)
else()
  target_compile_options(dnstoy PRIVATE -Wall -Wextra -Werror)
endif()

target_link_libraries( dnstoy ${Boost_LIBRARIES} pthread ssl crypto )