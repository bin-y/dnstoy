#ifndef DNSTOY_DNS_MESSAGE_DECODER_H_
#define DNSTOY_DNS_MESSAGE_DECODER_H_

#include <boost/endian/conversion.hpp>
#include <string>
#include <vector>
#include "dns_definition.hpp"

namespace dnstoy {
namespace dns {

class MessageDecoder {
 public:
  MessageDecoder();

  void reset();

  enum class ResultType { good, bad, indeterminate };
  ResultType ViewData(MessageView& message_view, const uint8_t* data,
                      size_t data_size, size_t& walked_size);
  static ResultType DecodeCompleteMesssage(Message& message,
                                           const uint8_t* buffer,
                                           size_t buffer_size);
  static ResultType ReadIDFromTcpMessage(const uint8_t* buffer,
                                         size_t buffer_size, int16_t& id);

 private:
  enum class FieldType {
    NAME,
    AFTER_NAME,
    RDATA,
  } waiting_field_ = FieldType::NAME;

  size_t waiting_data_size_ = sizeof(RawHeader);
  bool waiting_data_useful_ = true;
  size_t offset_in_message_ = 0;
  size_t* current_element_offset_ = nullptr;
  size_t* last_element_offset_ = nullptr;
  Message::Section current_section_ = Message::Section::HEADER;

  static ResultType DecodeName(std::string* name, const uint8_t* buffer,
                               size_t buffer_size, size_t from_offset,
                               bool follow_offset_label, size_t& max_offset);
  static ResultType DecodeQuestion(Question& question, const uint8_t* buffer,
                                   size_t buffer_size, size_t from_offset,
                                   size_t& end_offset);
  static ResultType DecodeResourceRecord(ResourceRecord& record,
                                         const uint8_t* buffer,
                                         size_t buffer_size, size_t from_offset,
                                         size_t& end_offset);
};

}  // namespace dns
}  // namespace dnstoy
#endif  // DNSTOY_DNS_MESSAGE_DECODER_H_