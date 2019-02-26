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
  auto encode_result = dns::MessageEncoder::Encode(
      response, buffer, offsetof(dns::RawTcpMessage, message));

  if (encode_result != ResultType::good) {
    return;
  }

  if (user_->type() == Remote::Type::UDP_USER) {
    if (buffer.size() > udp_payload_size_limit_) {
      // TODO: implement dns::MessageEncoder::Truncate
      // dns::MessageEncoder::Truncate(buffer, )
      return;
    }
  } else {
    auto message = reinterpret_cast<dns::RawTcpMessage*>(buffer.data());
    message->message_length = endian::native_to_big(
        buffer.size() - offsetof(dns::RawTcpMessage, message));
  }
  WriteMessage(std::move(buffer));
}

void Context::HandleUserMessage(MessageReader::Reason reason,
                                const uint8_t* data, uint16_t data_size) {
  using ResultType = dns::MessageDecoder::ResultType;
  auto query = std::make_shared<WithTimer<QueryContext>>();
  if (user_->type() == Remote::Type::UDP_USER) {
    LOG_TRACE("udp query");
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
  Resolve(query, std::bind(&Context::HandleResolvedQuery, shared_from_this(),
                           std::placeholders::_1));
}

void Context::HandleResolvedQuery(QueryContextPointer&& query) {
  auto& context = query->object;
  if (context.rcode != dns::RCODE::SUCCESS) {
    ReplyFailure(context.query.header.id, context.rcode);
    return;
  }
  if (context.query.questions.size()) {
    LOG_DEBUG("ID:" << context.query.header.id << " "
                    << context.query.questions[0].name << " resolved");
  }
  WriteMessage(std::move(query->object.raw_message));
}

void Context::WriteMessage(std::vector<uint8_t>&& tcp_raw_message) {
  write_message_queue_.emplace(std::move(tcp_raw_message));
  if (write_message_queue_.size() == 1) {
    DoWrite();
  }
}

void Context::DoWrite() {
  if (write_message_queue_.empty()) {
    return;
  }
  auto buffer = std::make_shared<vector<uint8_t>>(
      std::move(write_message_queue_.front()));
  write_message_queue_.pop();

  auto write_data = buffer->data();
  auto write_size = buffer->size();

  if (user_->type() == Remote::Type::UDP_USER) {
    write_data += offsetof(dns::RawTcpMessage, message);
    write_size -= offsetof(dns::RawTcpMessage, message);
  }

  user_->send(boost::asio::buffer(write_data, write_size),
              [this, _ = std::move(buffer), __ = shared_from_this()](
                  error_code error, size_t) { DoWrite(); });
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