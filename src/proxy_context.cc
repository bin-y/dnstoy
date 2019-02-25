#include <boost/endian/conversion.hpp>
#include <chrono>
#include <iostream>
#include <vector>
#include "configuration.hh"
#include "proxy.hh"
#include "tls_resolver.hh"

namespace dnstoy {
namespace proxy {
namespace endian = boost::endian;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using boost::system::error_code;
using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::chrono::milliseconds;

static auto configurations_initialized_ = false;
static uint16_t udp_payload_size_limit_ = 0;
static milliseconds query_timeout_;

Context::Context(Remote* user) : user_(user) {
  if (!configurations_initialized_) {
    udp_payload_size_limit_ =
        Configuration::get("udp-paylad-size-limit").as<uint16_t>();
    query_timeout_ =
        milliseconds(Configuration::get("query-timeout").as<uint32_t>());
    configurations_initialized_ = true;
  }
}

void Context::StartProcessUdpData(const uint8_t* data, size_t data_size) {
  HandleUserMessage(MessageReader::Reason::NEW_MESSAGE, data, data_size);
}

void Context::StartProcessStream() {
  if (user_->type() == Remote::Type::TCP_USER) {
    message_reader_.StartRead<tcp::socket>(
        *user_->GetTcpHandle(),
        std::bind(&Context::HandleUserMessage, shared_from_this(),
                  std::placeholders::_1, std::placeholders::_2,
                  std::placeholders::_3));
  }
}

void Context::ReplyFailure(int16_t id, dns::RCODE rcode) {
  LOG_DEBUG("ID:" << id << " failed, RCODE:" << static_cast<int16_t>(rcode));
  using ResultType = dns::MessageEncoder::ResultType;
  auto buffer_ptr = std::make_shared<vector<uint8_t>>();
  auto buffer = *buffer_ptr.get();
  size_t size_limit = 0;

  dns::Message response;
  response.header.id = id;
  response.header.response_code = static_cast<int16_t>(rcode);
  auto encode_result = dns::MessageEncoder::Encode(response, buffer, 0);
  if (encode_result != ResultType::good) {
    return;
  }

  if (user_->type() == Remote::Type::UDP_USER) {
    if (buffer.size() > udp_payload_size_limit_) {
      // TODO: implement dns::MessageEncoder::Truncate
      // dns::MessageEncoder::Truncate(buffer, )
      return;
    }
  }

  user_->send(boost::asio::buffer(buffer),
              [this, buffer_ptr = std::move(buffer_ptr),
               _ = shared_from_this()](error_code, size_t) {});
}

void Context::HandleUserMessage(MessageReader::Reason reason,
                                const uint8_t* data, uint16_t data_size) {
  using ResultType = dns::MessageDecoder::ResultType;
  auto query = std::make_shared<WithTimer<QueryContext>>();
  if (user_->type() == Remote::Type::UDP_USER) {
    auto decode_result = dns::MessageDecoder::DecodeCompleteMesssage(
        query->object.query, data, data_size);
    if (decode_result != ResultType::good) {
      LOG_ERROR("decode failed!");
      return;
    }
    query->object.raw_message.resize(
        sizeof(dns::RawTcpMessage::message_length));
    auto tcp_message =
        reinterpret_cast<dns::RawTcpMessage*>(query->object.raw_message.data());
    tcp_message->message_length = endian::native_to_big(data_size);
  } else {
    LOG_TRACE("tcp query");
    auto tcp_message = reinterpret_cast<const dns::RawTcpMessage*>(data);
    auto decode_result = dns::MessageDecoder::DecodeCompleteMesssage(
        query->object.query, tcp_message->message, tcp_message->message_length);
    if (decode_result != ResultType::good) {
      LOG_ERROR("decode failed!");
      return;
    }
  }
  query->object.raw_message.insert(query->object.raw_message.end(), data,
                                   data + data_size);
  query->ExpireSharedPtrAfter(query, query_timeout_);
  Resolve(query, [this, _ = shared_from_this()](QueryContextPointer&& query) {
    auto& context = query->object;
    if (context.rcode != dns::RCODE::SUCCESS) {
      ReplyFailure(context.query.header.id, context.rcode);
      return;
    }
    if (context.query.questions.size()) {
      LOG_DEBUG("ID:" << context.query.header.id << " "
                      << context.query.questions[0].name << " resolved");
    }
    auto send_data = query->object.raw_message.data();
    auto send_size = query->object.raw_message.size();
    if (user_->type() == Remote::Type::UDP_USER) {
      send_data += offsetof(dns::RawTcpMessage, message);
      send_size -= offsetof(dns::RawTcpMessage, message);
    }
    user_->send(boost::asio::buffer(send_data, send_size),
                [query = std::move(query)](error_code error, size_t) {});
  });
}
void Context::Resolve(QueryContextPointer& query_pointer,
                      QueryResultHandler&& handler) {
  static thread_local TlsResolver* tls_resolver_;
  if (!tls_resolver_) {
    // TODO: handle multiple server in configuration
    tls_resolver_ =
        new TlsResolver(Configuration::get("tls-servers").as<string>());
  }
  query_pointer->ExpireSharedPtrAfter(query_pointer, query_timeout_);
  // TODO: select resolver by rule
  tls_resolver_->Resolve(query_pointer, std::move(handler));
}

}  // namespace proxy
}  // namespace dnstoy