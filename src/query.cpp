#include "query.hpp"

namespace dnstoy {

void QueryManager::QueueQuery(QueryContext::weak_pointer&& context) {
  query_queue_.emplace_back(std::move(context));
}

void QueryManager::CutInQuery(QueryContext::weak_pointer&& context) {
  query_queue_.emplace_front(std::move(context));
}

size_t QueryManager::QueueSize() { return query_queue_.size(); }

bool QueryManager::GetQuery(QueryContext::pointer& record, int16_t& id) {
  while (query_queue_.size()) {
    record = query_queue_.front().lock();
    query_queue_.pop_front();
    if (record) {
      id = counter_++;
      return true;
    }
  }
  return false;
}

}  // namespace dnstoy
