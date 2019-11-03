#ifndef DNSTOY_TLS_RESOLVER_H_
#define DNSTOY_TLS_RESOLVER_H_
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>
#include <memory>
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
  void Resolve(QueryContext::pointer& query, QueryResultHandler& handler);

 private:
  using stream_type = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
  boost::asio::ssl::context ssl_context_;
  SSL_SESSION* ssl_session_ = nullptr;
  // NOTE:
  // do not use unique_ptr for stream as A stream object must not be destroyed
  // while there are pending asynchronous operations associated with it.
  // TODO:
  // implement a non-atomic shared_ptr for better performance
  std::shared_ptr<stream_type> socket_;
  uint16_t retry_connect_counter_ = 0;
  QueryManager query_manager_;
  std::string hostname_;
  tcp_endpoints_type endpoints_;
  std::unordered_map<int16_t, QueryManager::QueryRecord> sent_queries_;
  MessageReader message_reader_;
  std::chrono::seconds idle_timeout_ = std::chrono::seconds(30);
  boost::asio::steady_timer timeout_timer_;
  std::chrono::milliseconds first_retry_interval_ =
      std::chrono::milliseconds(500);
  std::chrono::milliseconds max_retry_interval_ =
      std::chrono::milliseconds(5 * 60 * 1000);
  boost::asio::steady_timer retry_timer_;
  enum class IOStatus {
    NOT_INITIALIZED,
    INITIALIZATION_DELAYED_FOR_RETRY,
    INITIALIZING,
    // keep it always bigger than READY the value of the status that requires
    // READY state
    READY,
    WRITING,
  } io_status_ = IOStatus::NOT_INITIALIZED;

  template <typename DurationType>
  void UpdateSocketTimeout(DurationType duration);
  void CloseConnection();
  void Reconnect();
  void Connect();
  void Handshake();
  void DoWrite();
  void HandleServerMessage(MessageReader::Reason reason, const uint8_t* data,
                           uint16_t data_size);
  void DropQuery(QueryManager::QueryRecord& record);
};

}  // namespace dnstoy
#endif  // DNSTOY_TLS_RESOLVER_H_