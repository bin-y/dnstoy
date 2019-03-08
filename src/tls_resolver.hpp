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

namespace dnstoy {

// thread-unsafe, designed for thread_local use
class TlsResolver {
 public:
  TlsResolver(const std::string& hostname);
  bool Init();
  void Resolve(QueryContext::weak_pointer&& query);

 private:
  using stream_type = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
  std::unique_ptr<stream_type> socket_;
  QueryManager query_manager_;
  std::string config_;
  std::string hostname_;
  std::variant<nullptr_t, boost::asio::ip::tcp::resolver::results_type,
               boost::asio::ip::tcp::endpoint>
      endpoints_;
  std::unordered_map<int16_t, QueryContext::weak_pointer> sent_queries_;
  MessageReader message_reader_;
  bool consuming_query_record_ = false;
  std::chrono::seconds idle_timeout_ = std::chrono::seconds(10);
  boost::asio::steady_timer timeout_timer_;

  template <typename DurationType>
  void UpdateSocketTimeout(DurationType duration);
  void CloseConnection();
  void ResetConnection();
  void Handshake();
  void DoWrite();
  void HandleServerMessage(MessageReader::Reason reason, const uint8_t* data,
                           uint16_t data_size);
  static boost::asio::ssl::context& GetSSLContextForConfig(
      const std::string& config);
};

}  // namespace dnstoy
#endif  // DNSTOY_TLS_RESOLVER_H_