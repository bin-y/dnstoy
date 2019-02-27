#ifndef DNSTOY_DNS_MESSAGE_ENCODER_H_
#define DNSTOY_DNS_MESSAGE_ENCODER_H_

#include <unordered_map>
#include <vector>
#include "dns_definition.hpp"

namespace dnstoy {
namespace dns {

class MessageEncoderContext;

class MessageEncoder {
 public:
  enum class ResultType { good, bad };
  static ResultType Encode(const Message& message, std::vector<uint8_t>& buffer,
                           size_t offset);
  static ResultType Truncate(std::vector<uint8_t>& buffer, size_t buffer_size,
                             size_t size_limit);
  static ResultType RewriteIDToTcpMessage(uint8_t* buffer, size_t buffer_size,
                                          int16_t id);
};

}  // namespace dns
}  // namespace dnstoy
#endif  // DNSTOY_DNS_MESSAGE_ENCODER_H_