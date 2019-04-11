#include "query.hpp"
#include <boost/asio.hpp>

namespace dnstoy {

void QueryManager::QueueQuery(QueryContext::weak_pointer&& context,
                              QueryResultHandler&& handler) {
  query_queue_.emplace_back(
      std::make_pair<QueryContext::weak_pointer, QueryResultHandler>(
          std::move(context), std::move(handler)));
}

void QueryManager::CutInQueryRecord(QueryRecord&& record) {
  query_queue_.emplace_front(std::move(record));
}

size_t QueryManager::QueueSize() { return query_queue_.size(); }

bool QueryManager::GetRecord(QueryRecord& record, int16_t& id) {
  while (query_queue_.size()) {
    auto& current = query_queue_.front();
    if (current.first.expired()) {
      current.second(std::move(current.first), boost::asio::error::timed_out);
      query_queue_.pop_front();
      continue;
    }
    record = std::move(current);
    id = counter_++;
    query_queue_.pop_front();
    return true;
  }
  return false;
}

}  // namespace dnstoy
