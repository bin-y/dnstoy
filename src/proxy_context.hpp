#ifndef DNSTOY_PROXY_CONTEXT_H_
#define DNSTOY_PROXY_CONTEXT_H_

#include <boost/asio.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <vector>
#include "configuration.hpp"
#include "dns.hpp"
#include "message_reader.hpp"
#include "proxy.hpp"
#include "query.hpp"

namespace dnstoy {
namespace proxy {

class Context : public std::enable_shared_from_this<Context> {
 public:
  using pointer = std::shared_ptr<Context>;

  static pointer create() { return pointer(new Context()); }

  template <typename TransportType>
  void Start(TransportType&& socket) {
    using UdpSocketType = boost::asio::ip::udp::socket;
    using TcpSocketType = boost::asio::ip::tcp::socket;
    socket_ = std::move(socket);
    static_assert(!std::is_same<TransportType, nullptr_t>::value,
                  "Can not start a proxy context with nullptr");
    if constexpr (std::is_same<TransportType, UdpSocketType>::value) {
      auto handler = std::bind(&Context::HandleUserMessage, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2,
                               std::placeholders::_3, std::placeholders::_4);
      message_reader_.resize_buffer(
          Configuration::get("udp-paylad-size-limit").as<uint16_t>());
      message_reader_.Start(std::get<UdpSocketType>(socket_), handler);
    } else {
      auto handler = std::bind(&Context::HandleUserMessage, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2,
                               std::placeholders::_3, nullptr);
      message_reader_.Start(std::get<TcpSocketType>(socket_), handler);
    }
  }
  void Stop();

 private:
  std::variant<nullptr_t, boost::asio::ip::tcp::socket,
               boost::asio::ip::udp::socket>
      socket_;
  MessageReader message_reader_;
  std::queue<QueryContextPointer> reply_queue_;

  Context() {}
  void ReplyFailure(QueryContextPointer&& query);
  void HandleUserMessage(MessageReader::Reason reason, const uint8_t* data,
                         uint16_t data_size,
                         const boost::asio::ip::udp::endpoint* udp_endpoint);
  void HandleResolvedQuery(QueryContextPointer&& query);
  static void Resolve(QueryContextPointer& query_pointer,
                      QueryResultHandler&& handler);
  void QueueReply(QueryContextPointer&& query);
  void DoWrite();
};

}  // namespace proxy
}  // namespace dnstoy
#endif  // DNSTOY_PROXY_CONTEXT_H_