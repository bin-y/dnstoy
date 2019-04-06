#include <boost/endian/conversion.hpp>
#include <chrono>
#include <iostream>
#include <vector>
#include "proxy.hpp"
#include "resolver.hpp"

namespace endian = boost::endian;
using boost::asio::async_write;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using boost::system::error_code;
using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::chrono::milliseconds;

namespace dnstoy {
namespace proxy {

void Context::Stop() {
  if (std::holds_alternative<boost::asio::ip::udp::socket>(socket_)) {
    error_code error;
    std::get<udp::socket>(socket_).close();
  } else {
    error_code error;
    std::get<tcp::socket>(socket_).close();
  }
}

void Context::ReplyFailure(QueryContext::pointer&& query) {
  auto id = query->query.header.id;
  auto rcode = query->rcode;
  LOG_DEBUG("ID:" << id << " failed, RCODE:" << static_cast<int16_t>(rcode));
  using ResultType = dns::MessageEncoder::ResultType;
  auto& buffer = query->raw_message;
  buffer.resize(0);
  size_t size_limit = 0;

  dns::Message response;
  response.header.id = id;
  response.header.is_response = true;
  response.header.response_code = static_cast<int16_t>(rcode);
  auto encode_result = dns::MessageEncoder::Encode(
      response, buffer, offsetof(dns::RawTcpMessage, message));

  if (encode_result != ResultType::good) {
    LOG_ERROR("Encode failure");
    return;
  }

  if (std::holds_alternative<boost::asio::ip::tcp::socket>(socket_)) {
    auto tcp_message = reinterpret_cast<dns::RawTcpMessage*>(buffer.data());
    tcp_message->message_length = endian::native_to_big(
        buffer.size() - offsetof(dns::RawTcpMessage, message));
  }
  QueueReply(std::move(query));
}

void Context::HandleUserMessage(
    MessageReader::Reason reason, const uint8_t* data, uint16_t data_size,
    const boost::asio::ip::udp::endpoint* udp_endpoint) {
  if (reason != MessageReader::Reason::NEW_MESSAGE) {
    LOG_TRACE("ignore reason:" << static_cast<int>(reason));
    return;
  }
  if (!data || !data_size) {
    LOG_ERROR("empty message!");
    return;
  }
  using ResultType = dns::MessageDecoder::ResultType;
  static auto query_timeout_ = std::chrono::milliseconds(
      Configuration::get("query-timeout").as<uint32_t>());
  auto query = QueryContextPool::get().get_object();
  uint16_t message_length = data_size;
  uint16_t message_offset = 0;
  if (udp_endpoint) {
    LOG_TRACE("udp query");
    query->endpoint = *udp_endpoint;
  } else {
    LOG_TRACE("tcp query");
    message_offset = offsetof(dns::RawTcpMessage, message);
    message_length -= offsetof(dns::RawTcpMessage, message);
  }
  auto decode_result = dns::MessageDecoder::DecodeCompleteMesssage(
      query->query, data + message_offset, message_length);
  if (decode_result != ResultType::good) {
    LOG_ERROR("decode failed!");
    return;
  }

  // store message as dns::RawTcpMessage
  query->raw_message.resize(offsetof(dns::RawTcpMessage, message) +
                            message_length);
  auto tcp_message =
      reinterpret_cast<dns::RawTcpMessage*>(query->raw_message.data());
  tcp_message->message_length = endian::native_to_big(message_length);
  memcpy(tcp_message->message, data + message_offset, message_length);

  query->handler = std::bind(&Context::HandleResolvedQuery, shared_from_this(),
                             std::placeholders::_1);
  query->LockPointerFor(query_timeout_);
  Resolver::Resolve(query);
}

void Context::HandleResolvedQuery(QueryContext::pointer&& query) {
  LOG_TRACE();
  auto& context = *query;
  if (context.rcode != dns::RCODE::SUCCESS) {
    ReplyFailure(std::move(query));
    return;
  }
  if (context.query.questions.size()) {
    LOG_DEBUG("ID:" << context.query.header.id << " "
                    << context.query.questions[0].name << " resolved");
  }
  QueueReply(std::move(query));
}

void Context::QueueReply(QueryContext::pointer&& query) {
  if (std::holds_alternative<boost::asio::ip::udp::socket>(socket_)) {
    static auto udp_payload_size_limit_ =
        Configuration::get("udp-paylad-size-limit").as<uint16_t>();

    auto& buffer = query->raw_message;
    auto tcp_message = reinterpret_cast<dns::RawTcpMessage*>(buffer.data());
    auto udp_payload_size =
        buffer.size() - offsetof(dns::RawTcpMessage, message);

    if (udp_payload_size > udp_payload_size_limit_) {
      using ResultType = dns::MessageEncoder::ResultType;
      size_t truncated_size;
      auto encode_result = dns::MessageEncoder::Truncate(
          tcp_message->message, udp_payload_size, udp_payload_size_limit_,
          truncated_size);
      if (encode_result != ResultType::good) {
        LOG_ERROR("Encode failure");
        return;
      }
      buffer.resize(truncated_size + offsetof(dns::RawTcpMessage, message));
    }
  }

  reply_queue_.emplace(std::move(query));
  DoWrite();
}

void Context::DoWrite() {
  if (writing_) {
    return;
  }
  if (reply_queue_.empty()) {
    return;
  }
  writing_ = true;
  auto query = std::move(reply_queue_.front());
  reply_queue_.pop();

  auto& endpoint = query->endpoint;
  auto write_data = query->raw_message.data();
  auto write_size = query->raw_message.size();

  auto handler = [this, _ = std::move(query), __ = shared_from_this()](
                     error_code error, size_t) {
    if (error) {
      LOG_ERROR(<< error.message());
    }
    writing_ = false;
    DoWrite();
  };

  if (std::holds_alternative<udp::socket>(socket_)) {
    auto& socket = std::get<udp::socket>(socket_);
    if (!socket.is_open()) {
      return;
    }
    write_data += offsetof(dns::RawTcpMessage, message);
    write_size -= offsetof(dns::RawTcpMessage, message);
    socket.async_send_to(boost::asio::buffer(write_data, write_size),
                         std::get<udp::endpoint>(endpoint), std::move(handler));
  } else {
    auto& socket = std::get<tcp::socket>(socket_);
    if (!socket.is_open()) {
      return;
    }
    async_write(socket, boost::asio::buffer(write_data, write_size),
                std::move(handler));
  }
}

}  // namespace proxy
}  // namespace dnstoy