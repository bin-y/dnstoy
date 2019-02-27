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

void QueryManager::QueueQuery(QueryContextWeakPointer&& context,
                              QueryResultHandler&& handler) {
  query_queue_.emplace(
      std::make_pair<QueryContextWeakPointer, QueryResultHandler>(
          std::move(context), std::move(handler)));
}

bool QueryManager::GetRecord(QueryRecord& record, int16_t& id) {
  while (query_queue_.size()) {
    auto& current = query_queue_.front();
    auto context = current.first.lock();
    if (context) {
      record = std::move(current);
      id = counter_++;
      query_queue_.pop();
      return true;
    }
    query_queue_.pop();
  }
  return false;
}

}  // namespace dnstoy
