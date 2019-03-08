#ifndef DNSTOY_QUERY_H_
#define DNSTOY_QUERY_H_
#include <boost/asio/steady_timer.hpp>
#include <memory>
#include <queue>
#include <unordered_map>
#include <variant>
#include <vector>
#include "dns.hpp"
#include "engine.hpp"

namespace dnstoy {

class QueryContext : public std::enable_shared_from_this<QueryContext> {
 public:
  using pointer = std::shared_ptr<QueryContext>;
  using weak_pointer = std::weak_ptr<QueryContext>;
  using TcpEndpoint = boost::asio::ip::tcp::endpoint;
  using UdpEndpoint = boost::asio::ip::udp::endpoint;
  std::variant<TcpEndpoint, UdpEndpoint> endpoint;
  dns::Message query;
  dns::Message answer;
  std::vector<uint8_t>
      raw_message;  // query or answer, with 2 octet tcp length field
  dns::RCODE rcode = dns::RCODE::SERVER_FAILURE;
  std::function<void(QueryContext::pointer&&)> handler;

  static pointer create() { return pointer(new QueryContext()); }

  template <typename DurationType>
  void LockPointerFor(DurationType duration) {
    TcpEndpoint a;
    timer_.expires_after(duration);
    timer_.async_wait([_ = shared_from_this()](boost::system::error_code) {});
  }

 private:
  QueryContext() : timer_(Engine::get().GetExecutor()) {}
  boost::asio::steady_timer timer_;
};

class QueryManager {
 public:
  void QueueQuery(QueryContext::weak_pointer&& context);
  bool GetQuery(QueryContext::pointer& context, int16_t& id);

 private:
  std::queue<QueryContext::weak_pointer> query_queue_;
  int16_t counter_;
};

}  // namespace dnstoy
#endif  // DNSTOY_QUERY_H_