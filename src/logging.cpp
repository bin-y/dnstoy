#include "logging.hpp"
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>

#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <iostream>
namespace dnstoy {

namespace expr = boost::log::expressions;

const auto date_time_formatter =
    expr::stream << expr::format_date_time<boost::posix_time::ptime>(
                        "TimeStamp", "e[15m%m%d %H:%M:%S.%f")
                 << expr::message;

void InitLogging() {
  boost::log::add_common_attributes();
  boost::log::add_console_log()->set_formatter(date_time_formatter);
  ;
}

}  // namespace dnstoy