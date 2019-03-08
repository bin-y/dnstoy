#include "query.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <queue>
#include <vector>
#include "configuration.hpp"
#include "engine.hpp"

using boost::asio::signal_set;
namespace ssl = boost::asio::ssl;
using boost::asio::ip::make_address;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using boost::system::error_code;
using std::atomic;
using std::cout;
using std::endl;

namespace dnstoy {

void QueryManager::QueueQuery(QueryContext::weak_pointer&& context) {
  query_queue_.emplace(std::move(context));
}

bool QueryManager::GetQuery(QueryContext::pointer& record, int16_t& id) {
  while (query_queue_.size()) {
    record = query_queue_.front().lock();
    query_queue_.pop();
    if (record) {
      id = counter_++;
      return true;
    }
  }
  return false;
}

}  // namespace dnstoy
