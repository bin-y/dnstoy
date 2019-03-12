#ifndef DNSTOY_LOGGING_H_
#define DNSTOY_LOGGING_H_

#include <boost/log/trivial.hpp>

namespace dnstoy {
void InitLogging();
}  // namespace dnstoy

#define DNSTOY_LOG_TRIVIAL2(severity, color, line) \
  BOOST_LOG_TRIVIAL(severity)                      \
      << color __FILE__ ":" #line " " << __FUNCTION__ << ": "

#define DNSTOY_LOG_TRIVIAL(severity, color, line) \
  DNSTOY_LOG_TRIVIAL2(severity, color, line)

#ifdef NDEBUG
#define LOG_TRACE(expression)
#define LOG_DEBUG(expression)
#else
#define LOG_TRACE(expression) \
  DNSTOY_LOG_TRIVIAL(trace, "\e[90m", __LINE__) expression
#define LOG_DEBUG(expression) \
  DNSTOY_LOG_TRIVIAL(debug, "\e[37m", __LINE__) expression
#endif

#define LOG_INFO(expression) \
  DNSTOY_LOG_TRIVIAL(info, "\e[39m", __LINE__) expression
#define LOG_ERROR(expression) \
  DNSTOY_LOG_TRIVIAL(error, "\e[91m", __LINE__) expression

#endif  // DNSTOY_LOGGING_H_