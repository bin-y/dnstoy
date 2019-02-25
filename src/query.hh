#ifndef DNSTOY_QUERY_H_
#define DNSTOY_QUERY_H_
#include <memory>
#include <queue>
#include <unordered_map>
#include <vector>
#include "dns.hh"
#include "with_timer.hh"

namespace dnstoy {

struct QueryContext {
  dns::Message query;
  dns::Message answer;
  std::vector<uint8_t>
      raw_message;  // query or answer, with 2 octet tcp length field
  dns::RCODE rcode = dns::RCODE::SERVER_FAILURE;
};

using QueryContextPointer = WithTimer<QueryContext>::pointer;
using QueryContextWeakPointer = WithTimer<QueryContext>::weak_pointer;
using QueryResultHandler = std::function<void(QueryContextPointer&&)>;

class QueryManager {
 public:
  using QueryRecord = std::pair<QueryContextWeakPointer, QueryResultHandler>;
  void QueueQuery(QueryContextWeakPointer&& context,
                  QueryResultHandler&& handler);
  bool GetRecord(
      QueryRecord& record,
      int16_t& id);  // Get a query record which query context is not expired

 private:
  static int16_t CreateID();
  std::queue<QueryRecord> query_queue_;
};

}  // namespace dnstoy
#endif  // DNSTOY_QUERY_H_