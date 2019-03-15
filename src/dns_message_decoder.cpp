#include <boost/endian/conversion.hpp>
#include <string>
#include <vector>
#include "dns.hpp"
#include "logging.hpp"

namespace endian = boost::endian;
using std::string;
using std::vector;

namespace dnstoy {
namespace dns {

MessageDecoder::MessageDecoder() {}

#define READ_FLAG(FLAGS_, FLAG_NAME_)                 \
  ((RawHeader::Flag::FLAG_NAME_##_mask & (FLAGS_)) >> \
   RawHeader::Flag::FLAG_NAME_##_offset)

void MessageDecoder::reset() {
  current_section_ = Message::Section::HEADER;
  waiting_data_size_ = sizeof(RawHeader);
  waiting_data_is_useful_ = true;
  offset_in_message_ = 0;
  current_element_offset_ = nullptr;
  last_element_offset_ = nullptr;
}

MessageDecoder::ResultType MessageDecoder::ViewData(MessageView& message,
                                                    const uint8_t* data,
                                                    size_t data_size,
                                                    size_t& walked_size) {
  walked_size = 0;
  auto move_offset = [this, &walked_size](size_t size) {
    walked_size += size;
    offset_in_message_ += size;
  };
  while (true) {
    if (data_size < waiting_data_size_) {
      if (!waiting_data_is_useful_) {
        move_offset(data_size);
        waiting_data_size_ -= data_size;
      }
      return ResultType::indeterminate;
    }

    if (walked_size == data_size) {
      return ResultType::indeterminate;
    }

    auto begin = data + walked_size;
    size_t size = data_size - walked_size;

    if (current_section_ == Message::Section::HEADER) {
      // decode header
      auto& header = *reinterpret_cast<const RawHeader*>(data);
      message.id = endian::big_to_native(header.ID);
      message.answer_count = endian::big_to_native(header.ANCOUNT);
      message.authority_count = endian::big_to_native(header.NSCOUNT);
      message.additional_count = endian::big_to_native(header.ARCOUNT);
      size_t resource_record_count = message.answer_count +
                                     message.authority_count +
                                     message.additional_count;

      // check question & resource record count
      if (resource_record_count) {
        message.resource_record_offsets.resize(resource_record_count, 0);
        current_element_offset_ = message.resource_record_offsets.data();
        last_element_offset_ = &message.resource_record_offsets.back();
        current_section_ = Message::Section::ANSWER;
      }
      if (header.QDCOUNT) {
        message.question_offsets.resize(endian::big_to_native(header.QDCOUNT),
                                        0);
        current_element_offset_ = message.question_offsets.data();
        last_element_offset_ = &message.question_offsets.back();
        current_section_ = Message::Section::QUESTION;
      }

      // header decoded
      move_offset(sizeof(RawHeader));

      if (current_section_ == Message::Section::HEADER) {
        // message have not any question or resource record
        message.size = offset_in_message_;
        return ResultType::good;
      }
      waiting_field_ = FieldType::NAME;
      waiting_data_size_ = 0;
      continue;
    }
    if (waiting_field_ == FieldType::NAME) {
      // begining of question / resource record
      if (*current_element_offset_ == 0) {
        *current_element_offset_ = offset_in_message_;
      }
      size_t max_offset = 0;
      auto result = DecodeName(nullptr, begin, size, 0, false, max_offset);
      move_offset(max_offset);

      if (result != ResultType::good) {
        return result;
      }
      waiting_field_ = FieldType::AFTER_NAME;
      switch (current_section_) {
        case Message::Section::QUESTION: {
          waiting_data_size_ = sizeof(RawQuestion) - sizeof(RawQuestion::QNAME);
          waiting_data_is_useful_ = false;
        } break;
        case Message::Section::ANSWER:
        case Message::Section::AUTHORITY:
        case Message::Section::ADDITIONAL: {
          waiting_data_size_ =
              sizeof(RawResourceRecord) - sizeof(RawResourceRecord::NAME);
          waiting_data_is_useful_ = true;
        } break;
        default:
          assert(false);
          return ResultType::bad;
          break;
      }
      continue;
    }
    if (waiting_field_ == FieldType::AFTER_NAME) {
      switch (current_section_) {
        case Message::Section::QUESTION: {
          // end of question field
          waiting_field_ = FieldType::NAME;
          waiting_data_size_ = 0;
          waiting_data_is_useful_ = true;
          if (current_element_offset_ == last_element_offset_) {
            if (message.resource_record_offsets.size()) {
              current_section_ = Message::Section::ANSWER;
              current_element_offset_ = message.resource_record_offsets.data();
              last_element_offset_ = &message.resource_record_offsets.back();
            } else {
              message.size = offset_in_message_;
              return ResultType::good;
            }
          } else {
            current_element_offset_++;
          }
        } break;
        case Message::Section::ANSWER:
        case Message::Section::AUTHORITY:
        case Message::Section::ADDITIONAL: {
          // middle of resource record
          auto field_size =
              sizeof(RawResourceRecord) - sizeof(RawResourceRecord::NAME);
          auto record = reinterpret_cast<const RawResourceRecord*>(
              begin - sizeof(RawResourceRecord::NAME));
          move_offset(field_size);
          // read rd size from resource record and wait for it
          waiting_data_size_ = endian::big_to_native(record->RDLENGTH);
          waiting_data_is_useful_ = false;
        } break;
        default:
          assert(false);
          return ResultType::bad;
          break;
      }
      continue;
    }
    if (waiting_field_ == FieldType::RDATA) {
      // end of resource field
      if (current_element_offset_ == last_element_offset_) {
        message.size = offset_in_message_;
        return ResultType::good;
      } else {
        current_element_offset_++;
        waiting_field_ = FieldType::NAME;
        waiting_data_size_ = 0;
        waiting_data_is_useful_ = true;
      }
      continue;
    }
    assert(false);
    LOG_ERROR();
    return ResultType::bad;
  }
}

MessageDecoder::ResultType MessageDecoder::DecodeCompleteMesssage(
    Message& message, const uint8_t* buffer, size_t buffer_size) {
  size_t offset = 0;
  {
    if (buffer_size < offset + sizeof(RawHeader)) {
      return ResultType::bad;
    }
    // decode header
    auto& header = *reinterpret_cast<const RawHeader*>(buffer);
    message.header.id = endian::big_to_native(header.ID);
    message.header.isResponse = READ_FLAG(header.FLAGS, QR);
    message.header.operation = READ_FLAG(header.FLAGS, Opcode);
    message.header.isAuthoritativeAnswer = READ_FLAG(header.FLAGS, AA);
    message.header.isTruncated = READ_FLAG(header.FLAGS, TC);
    message.header.isRecursionDesired = READ_FLAG(header.FLAGS, RD);
    message.header.isRecursionAvailable = READ_FLAG(header.FLAGS, RA);
    message.header.z = READ_FLAG(header.FLAGS, Z);
    message.header.response_code = READ_FLAG(header.FLAGS, RCODE);

    if (header.ARCOUNT) {
      message.additional.resize(endian::big_to_native(header.ARCOUNT));
    }
    if (header.NSCOUNT) {
      message.authorities.resize(endian::big_to_native(header.NSCOUNT));
    }
    if (header.ANCOUNT) {
      message.answers.resize(endian::big_to_native(header.NSCOUNT));
    }
    if (header.QDCOUNT) {
      message.questions.resize(endian::big_to_native(header.QDCOUNT));
    }
    offset += sizeof(RawHeader);
  }

  for (auto& question : message.questions) {
    auto result = DecodeQuestion(question, buffer, buffer_size, offset, offset);
    if (result != ResultType::good) {
      return result;
    }
  }

  for (auto& record : message.answers) {
    auto result =
        DecodeResourceRecord(record, buffer, buffer_size, offset, offset);
    if (result != ResultType::good) {
      return result;
    }
  }

  for (auto& record : message.authorities) {
    auto result =
        DecodeResourceRecord(record, buffer, buffer_size, offset, offset);
    if (result != ResultType::good) {
      return result;
    }
  }

  for (auto& record : message.additional) {
    auto result =
        DecodeResourceRecord(record, buffer, buffer_size, offset, offset);
    if (result != ResultType::good) {
      return result;
    }
  }
  return ResultType::good;
}

inline MessageDecoder::ResultType MessageDecoder::DecodeName(
    std::string* name, const uint8_t* buffer, size_t buffer_size,
    size_t from_offset, bool follow_offset_label, size_t& max_offset) {
  auto jumped = false;
  max_offset = from_offset;
  while (true) {
    auto label = reinterpret_cast<const RawLabel*>(buffer + from_offset);
    if (from_offset > buffer_size) {
      return ResultType::bad;
    }
    if (from_offset == buffer_size) {
      return ResultType::indeterminate;
    }
    switch (label->flag & RawLabel::Flag::MASK) {
      case RawLabel::Flag::OFFSET: {
        // rfc1035 4.1.4. Message compression
        constexpr auto label_size = 2;
        if (from_offset + label_size > buffer_size) {
          return ResultType::indeterminate;
        }
        if (!jumped) {
          max_offset += label_size;
        }

        auto to_offset = (label->offset_type.offset_high << 8) |
                         label->offset_type.offset_low;

        if (to_offset >= from_offset) {
          // offset should point to the label occured before
          return ResultType::bad;
        }

        if (!follow_offset_label) {
          return ResultType::good;
        }

        from_offset = to_offset;
        jumped = true;
      } break;
      case RawLabel::Flag::NORMAL: {
        const auto label_size = label->normal_type.data_length +
                                sizeof(label->normal_type.data_length);
        if (from_offset + label_size > buffer_size) {
          return ResultType::indeterminate;
        }
        if (!jumped) {
          max_offset += label_size;
        }

        if (label->normal_type.data_length == 0) {
          return ResultType::good;
        } else {
          if (name != nullptr) {
            if (name->size()) {
              *name += ".";
            }
            name->append(
                label->normal_type.data,
                label->normal_type.data + label->normal_type.data_length);
          }

          from_offset += label_size;
        }
      } break;
      default:
        // rfc1035 4.1.4: 0x40/0x80 reserved for future
        assert(false);
        return ResultType::bad;
    }
  }
}

inline MessageDecoder::ResultType MessageDecoder::DecodeQuestion(
    Question& question, const uint8_t* buffer, size_t buffer_size,
    size_t from_offset, size_t& end_offset) {
  auto result = DecodeName(&question.name, buffer, buffer_size, from_offset,
                           true, from_offset);
  if (result != ResultType::good) {
    return ResultType::bad;
  }

  auto fields_size = sizeof(RawQuestion) - sizeof(RawQuestion::QNAME);
  if (from_offset + fields_size > buffer_size) {
    return ResultType::bad;
  }
  auto raw_question = reinterpret_cast<const RawQuestion*>(
      buffer + from_offset - sizeof(RawQuestion::QNAME));
  question.type = endian::big_to_native(raw_question->QTYPE);
  question.the_class = endian::big_to_native(raw_question->QCLASS);
  end_offset = from_offset + fields_size;
  return ResultType::good;
}

inline MessageDecoder::ResultType MessageDecoder::DecodeResourceRecord(
    ResourceRecord& record, const uint8_t* buffer, size_t buffer_size,
    size_t from_offset, size_t& end_offset) {
  auto result = DecodeName(&record.name, buffer, buffer_size, from_offset, true,
                           from_offset);
  if (result != ResultType::good) {
    return ResultType::bad;
  }
  auto fields_before_rdata_size =
      sizeof(RawResourceRecord) - sizeof(RawResourceRecord::NAME);
  if (from_offset + fields_before_rdata_size > buffer_size) {
    return ResultType::bad;
  }
  auto raw_record = reinterpret_cast<const RawResourceRecord*>(
      buffer + from_offset - sizeof(RawResourceRecord::NAME));
  record.type = endian::big_to_native(raw_record->TYPE);
  record.the_class = endian::big_to_native(raw_record->CLASS);
  record.ttl = endian::big_to_native(raw_record->TTL);
  auto rdata_size = endian::big_to_native(raw_record->RDLENGTH);

  if (from_offset + fields_before_rdata_size + rdata_size > buffer_size) {
    return ResultType::bad;
  }
  record.rdata.assign(raw_record->RDATA, raw_record->RDATA + rdata_size);

  end_offset = from_offset + fields_before_rdata_size + rdata_size;
  return ResultType::good;
}

MessageDecoder::ResultType MessageDecoder::ReadIDFromTcpMessage(
    const uint8_t* buffer, size_t buffer_size, int16_t& id) {
  constexpr auto read_offset =
      offsetof(dns::RawTcpMessage, message) + offsetof(dns::RawHeader, ID);
  constexpr auto read_size = sizeof(dns::RawHeader::ID);
  if (buffer_size < read_offset + read_size) {
    return ResultType::bad;
  }
  id = boost::endian::big_to_native(
      *reinterpret_cast<const decltype(dns::RawHeader::ID)*>(buffer +
                                                             read_offset));
  return ResultType::good;
}

}  // namespace dns
}  // namespace dnstoy