#ifndef DNSTOY_TLS_RESOLVER_H_
#define DNSTOY_TLS_RESOLVER_H_
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>
#include <string>
#include <unordered_map>
#include "message_reader.hh"
#include "query.hh"

namespace dnstoy {

class TlsResolver {
 public:
  TlsResolver(const std::string& hostname);
  void Resolve(QueryContextWeakPointer&& query, QueryResultHandler&& handler);

 private:
  using stream_type = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
  std::unique_ptr<stream_type> socket_;
  QueryManager query_manager_;
  std::string hostname_;
  boost::asio::ip::tcp::resolver::results_type endpoints_;
  std::unordered_map<int16_t, QueryManager::QueryRecord> sent_queries_;
  MessageReader message_reader_;
  QueryManager::QueryRecord* reading_record_ = nullptr;
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
  static boost::asio::ssl::context& GetSSLContextForHost(
      const std::string& hostname);
};

}  // namespace dnstoy
#endif  // DNSTOY_TLS_RESOLVER_H_