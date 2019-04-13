#ifndef DNSTOY_QUERY_H_
#define DNSTOY_QUERY_H_
#include <boost/asio/steady_timer.hpp>
#include <deque>
#include <memory>
#include <unordered_map>
#include <variant>
#include <vector>
#include "dns.hpp"
#include "engine.hpp"
#include "shared_object_pool.hpp"

namespace dnstoy {

class QueryContext : public std::enable_shared_from_this<QueryContext> {
 public:
  using pointer = std::shared_ptr<QueryContext>;
  using TcpEndpoint = boost::asio::ip::tcp::endpoint;
  using UdpEndpoint = boost::asio::ip::udp::endpoint;
  std::variant<TcpEndpoint, UdpEndpoint> endpoint;
  dns::Message query;
  dns::Message answer;
  std::vector<uint8_t>
      raw_message;  // query or answer in dns::RawTcpMessage format
  size_t pending_resolve_attempt = 0;

  enum class Status {
    WAITING_FOR_ANSWER,
    ANSWER_WRITTERN_TO_BUFFER,
    ANSWER_ACCEPTED,
    EXPIRED
  } status = Status::WAITING_FOR_ANSWER;

  static pointer create() { return pointer(new QueryContext()); }

  template <typename DeleterType>
  static pointer create_with_deleter(DeleterType&& deleter) {
    return pointer(new QueryContext(), std::forward<DeleterType>(deleter));
  }

  template <typename DurationType>
  void ExpiresAfter(DurationType duration) {
    TcpEndpoint a;
    timer_.expires_after(duration);
    timer_.async_wait(
        [self = shared_from_this()](boost::system::error_code error) {
          if (!error) {
            if (self->status == Status::WAITING_FOR_ANSWER) {
              self->status = Status::EXPIRED;
            }
          }
        });
  }

  void CancelExpireTimer() { timer_.cancel(); }

  void on_recycled_by_object_pool() {
    // endpoint = TcpEndpoint{};
    query.reset();
    answer.reset();
    raw_message.clear();
    status = Status::WAITING_FOR_ANSWER;
  }

 private:
  QueryContext() : timer_(Engine::get().GetExecutor()) {}
  boost::asio::steady_timer timer_;
};

using QueryContextPool = SharedObjectPool<
    QueryContext, 64,
    SharedObjectPoolObjectCreationMethod::
        CreateAndCreateWithDeleterFunctionReturningSharedPointer>;

using QueryResultHandler =
    std::function<void(QueryContext::pointer&&, boost::system::error_code)>;

class QueryManager {
 public:
  using QueryRecord = std::pair<QueryContext::pointer, QueryResultHandler>;
  void QueueQuery(QueryContext::pointer& context, QueryResultHandler& handler);
  void CutInQueryRecord(QueryRecord&& record);
  size_t QueueSize();
  bool GetRecord(QueryRecord& record, int16_t& id);

 private:
  std::deque<QueryRecord> query_queue_;
  int16_t counter_;
};

}  // namespace dnstoy
#endif  // DNSTOY_QUERY_H_