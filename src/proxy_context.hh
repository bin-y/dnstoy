#ifndef DNSTOY_PROXY_CONTEXT_H_
#define DNSTOY_PROXY_CONTEXT_H_

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include "dns.hh"
#include "message_reader.hh"
#include "proxy.hh"
#include "query.hh"

namespace dnstoy {
namespace proxy {

class Context : public std::enable_shared_from_this<Context> {
 public:
  using pointer = std::shared_ptr<Context>;

  static pointer create(Remote* user) { return pointer(new Context(user)); }

  void StartProcessStream();
  void StartProcessUdpData(const uint8_t* data, size_t data_size);

 private:
  std::unique_ptr<Remote> user_;
  MessageReader message_reader_;
  dns::MessageDecoder message_decoder_;

  void ReplyFailure(int16_t id, dns::RCODE rcode);
  void HandleUserMessage(MessageReader::Reason reason, const uint8_t* data,
                         uint16_t data_size);
  static void Resolve(QueryContextPointer& query_pointer,
                      QueryResultHandler&& handler);
  Context(Remote* user);
};

}  // namespace proxy
}  // namespace dnstoy
#endif  // DNSTOY_PROXY_CONTEXT_H_