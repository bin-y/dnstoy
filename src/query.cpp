#include "query.hpp"
#include <boost/asio.hpp>

namespace dnstoy {

void QueryManager::QueueQuery(QueryContext::pointer& context,
                              QueryResultHandler& handler) {
  query_queue_.emplace_back(
      std::pair<QueryContext::pointer, QueryResultHandler>(context, handler));
}

void QueryManager::CutInQueryRecord(QueryRecord&& record) {
  query_queue_.emplace_front(std::move(record));
}

size_t QueryManager::QueueSize() { return query_queue_.size(); }

bool QueryManager::GetRecord(QueryRecord& record, int16_t& id) {
  if (query_queue_.size()) {
    auto& current = query_queue_.front();
    record = std::move(current);
    id = counter_++;
    query_queue_.pop_front();
    return true;
  }
  return false;
}

}  // namespace dnstoy
