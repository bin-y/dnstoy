#include <algorithm>
#include <boost/endian/conversion.hpp>
#include <functional>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>
#include "dns.hpp"

namespace endian = boost::endian;
using std::string;
using std::unordered_map;
using std::vector;

namespace dnstoy {
namespace dns {

class MessageEncoderContext {
 public:
  MessageEncoderContext(std::vector<uint8_t>& arg_buffer, size_t arg_offset)
      : buffer(arg_buffer), offset(arg_offset) {}
  std::vector<uint8_t>& buffer;
  size_t offset;
  std::unordered_map<std::string, size_t> encoded_labels;
};

#define WRITE_FLAG(FLAGS_, FLAG_NAME_, VALUE_)                      \
  (FLAGS_) = ((FLAGS_ & (~RawHeader::Flag::FLAG_NAME_##_mask)) |    \
              (((VALUE_) << RawHeader::Flag::FLAG_NAME_##_offset) & \
               RawHeader::Flag::FLAG_NAME_##_mask))

#define SAFE_SET_INT(TO_, FROM_)                               \
  do {                                                         \
    if (std::numeric_limits<decltype(TO_)>::max() < (FROM_)) { \
      return MessageEncoder::ResultType::bad;                  \
    }                                                          \
    (TO_) = endian::native_to_big(FROM_);                      \
  } while (false)

inline bool EncodeName(MessageEncoderContext& context, const string& name) {
  string::size_type end_offset;
  auto begin_offset = 0;

  do {
    auto i = context.encoded_labels.find(&name[begin_offset]);
    if (i != context.encoded_labels.end()) {
      context.buffer.resize(context.offset + 2);
      auto label =
          reinterpret_cast<RawLabel*>(context.buffer.data() + context.offset);
      label->offset_type.offset_high = (i->second >> 8) & 0xFF;
      label->offset_type.offset_low = i->second & 0xFF;
      label->flag |= RawLabel::Flag::OFFSET;
      context.offset += 2;
      return true;
    }

    end_offset = name.find('.');
    if (end_offset == string::npos) {
      end_offset = name.size();
    }
    if (end_offset == begin_offset) {
      return false;
    }
    auto label_length = end_offset - begin_offset;
    if (label_length > std::numeric_limits<uint8_t>::max()) {
      return false;
    }
    context.buffer.push_back(label_length);
    context.buffer.insert(context.buffer.end(), &name[begin_offset],
                          &name[end_offset]);
    if (label_length > 1) {
      context.encoded_labels[&name[begin_offset]] = context.offset;
    }
    context.offset += 1 + label_length;
  } while (end_offset != name.size());
  context.buffer.push_back(0);
  context.offset += 1;
  return true;
}

inline MessageEncoder::ResultType EncodeResourceRecord(
    MessageEncoderContext& context, const ResourceRecord& record) {
  if (!EncodeName(context, record.name)) {
    return MessageEncoder::ResultType::bad;
  }

  auto fields_before_rdata_size =
      sizeof(RawResourceRecord) - sizeof(RawResourceRecord::NAME);
  auto raw_record = reinterpret_cast<RawResourceRecord*>(
      context.buffer.data() + context.offset - sizeof(RawResourceRecord::NAME));

  raw_record->TYPE = endian::native_to_big(record.type);
  raw_record->CLASS = endian::native_to_big(record.the_class);
  raw_record->TTL = endian::native_to_big(record.ttl);
  SAFE_SET_INT(raw_record->RDLENGTH, record.rdata.size());
  context.buffer.insert(context.buffer.end(), record.rdata.begin(),
                        record.rdata.end());
  return MessageEncoder::ResultType::good;
}

MessageEncoder::ResultType MessageEncoder::Encode(const Message& message,
                                                  std::vector<uint8_t>& buffer,
                                                  size_t offset) {
  MessageEncoderContext context(buffer, offset);
  buffer.reserve(offset + 512);

  {
    // encode header
    context.buffer.resize(context.buffer.size() + sizeof(RawHeader), 0);
    auto& source = message.header;
    buffer.resize(sizeof(RawHeader));
    auto destination = reinterpret_cast<RawHeader*>(buffer.data());
    destination->ID = endian::native_to_big(source.id);
    WRITE_FLAG(destination->FLAGS, QR, source.isQuery);
    WRITE_FLAG(destination->FLAGS, Opcode, source.operation);
    WRITE_FLAG(destination->FLAGS, AA, source.isAuthoritativeAnswer);
    WRITE_FLAG(destination->FLAGS, TC, source.isTruncated);
    WRITE_FLAG(destination->FLAGS, RD, source.isRecursionDesired);
    WRITE_FLAG(destination->FLAGS, RA, source.isRecursionAvailable);
    WRITE_FLAG(destination->FLAGS, Z, source.z);
    WRITE_FLAG(destination->FLAGS, RCODE, source.response_code);
    SAFE_SET_INT(destination->QDCOUNT, message.questions.size());
    SAFE_SET_INT(destination->ANCOUNT, message.answers.size());
    SAFE_SET_INT(destination->NSCOUNT, message.authorities.size());
    SAFE_SET_INT(destination->ARCOUNT, message.additional.size());

    context.offset += sizeof(RawHeader);
  }

  for (auto& question : message.questions) {
    if (!EncodeName(context, question.name)) {
      return MessageEncoder::ResultType::bad;
    }
    auto field_size = sizeof(RawQuestion) - sizeof(RawQuestion::QNAME);
    context.buffer.resize(context.offset + field_size);
    auto raw_question = reinterpret_cast<RawQuestion*>(
        buffer.data() + offset - sizeof(RawQuestion::QNAME));
    raw_question->QTYPE = endian::native_to_big(question.type);
    raw_question->QCLASS = endian::native_to_big(question.the_class);
    context.offset += field_size;
  }

  for (auto& record : message.answers) {
    auto result = EncodeResourceRecord(context, record);
    if (result != ResultType::good) {
      return result;
    }
  }

  for (auto& record : message.authorities) {
    auto result = EncodeResourceRecord(context, record);
    if (result != ResultType::good) {
      return result;
    }
  }

  for (auto& record : message.additional) {
    auto result = EncodeResourceRecord(context, record);
    if (result != ResultType::good) {
      return result;
    }
  }
  return ResultType::good;
}

MessageEncoder::ResultType MessageEncoder::RewriteIDToTcpMessage(
    uint8_t* buffer, size_t buffer_size, int16_t id) {
  constexpr auto write_offset =
      offsetof(dns::RawTcpMessage, message) + offsetof(dns::RawHeader, ID);
  constexpr auto write_size = sizeof(dns::RawHeader::ID);
  if (buffer_size < write_size + write_size) {
    return ResultType::bad;
  }
  *reinterpret_cast<decltype(dns::RawHeader::ID)*>(buffer + write_offset) =
      boost::endian::native_to_big(id);
  return ResultType::good;
}

}  // namespace dns
}  // namespace dnstoy