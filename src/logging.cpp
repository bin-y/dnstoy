#include "logging.hpp"
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>

namespace dnstoy {

void InitLogging() {
  boost::log::add_common_attributes();
  boost::log::add_console_log();
}

}  // namespace dnstoy