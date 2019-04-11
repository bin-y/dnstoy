#ifndef DNSTOY_TLS_RESOLVER_H_
#define DNSTOY_TLS_RESOLVER_H_
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>
#include <string>
#include <unordered_map>
#include <variant>
#include "message_reader.hpp"
#include "query.hpp"
#include "resolver.hpp"

namespace dnstoy {

// thread-unsafe, designed for thread_local use
class TlsResolver {
 public:
  using tcp_endpoints_type = std::vector<boost::asio::ip::tcp::endpoint>;
  TlsResolver(const std::string& hostname, const tcp_endpoints_type& endpoints);
  void Resolve(QueryContext::weak_pointer&& query,
               QueryResultHandler&& handler);

 private:
  using stream_type = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
  boost::asio::ssl::context ssl_context_;
  std::unique_ptr<stream_type> socket_;
  QueryManager query_manager_;
  std::string hostname_;
  tcp_endpoints_type endpoints_;
  std::unordered_map<int16_t, QueryManager::QueryRecord> sent_queries_;
  MessageReader message_reader_;
  std::chrono::seconds idle_timeout_ = std::chrono::seconds(10);
  boost::asio::steady_timer timeout_timer_;
  enum class IOStatus {
    NOT_INITIALIZED,
    INITIALIZATION_FAILED,
    INITIALIZING,
    READY,
    WRITING,
  } io_status_ = IOStatus::NOT_INITIALIZED;

  template <typename DurationType>
  void UpdateSocketTimeout(DurationType duration);
  void CloseConnection();
  void ResetConnection();
  void Handshake();
  void DoWrite();
  void HandleServerMessage(MessageReader::Reason reason, const uint8_t* data,
                           uint16_t data_size);
};

}  // namespace dnstoy
#endif  // DNSTOY_TLS_RESOLVER_H_