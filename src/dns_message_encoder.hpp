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

  static ResultType Truncate(uint8_t* buffer, size_t buffer_size,
                             size_t size_limit, size_t& truncated_size);
  static ResultType RewriteIDToTcpMessage(uint8_t* buffer, size_t buffer_size,
                                          int16_t id);
  static ResultType EncodeEDNS0ClientSubnetResoureceRecord(
      std::vector<uint8_t>& buffer, uint16_t udp_payload_size,
      EDNSOption::ClientSubnet& options, const uint8_t* address);
  static ResultType AppendAdditionalResourceRecordToRawTcpMessage(
      std::vector<uint8_t>& message_buffer, const uint8_t* raw_resource_record,
      uint16_t raw_resource_record_length);
};

}  // namespace dns
}  // namespace dnstoy
#endif  // DNSTOY_DNS_MESSAGE_ENCODER_H_