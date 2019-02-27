#ifndef DNSTOY_DNS_DEFINITION_H_
#define DNSTOY_DNS_DEFINITION_H_
#include <string>
#include <vector>
#include "dns_definition_raw.hpp"

namespace dnstoy {
namespace dns {
// ref: rfc1035 4.1. Format

/*
 According to The Transparency Principle in rfc5625,
 this project is not validating value in payloads for maxmium compatibility,
 so following enums is not used in struct definition.
 */

enum class OPCODE : int16_t { QUERY = 0, IQUERY, STATUS };

enum class RCODE : int16_t {
  SUCCESS = 0,
  FORMAT_ERRROR,
  SERVER_FAILURE,
  NAME_ERROR,
  NOT_IMPLEMENTED,
  REFUSED
};

enum class TYPE : int16_t {
  A = 1,      // a host address
  NS,         // an authoritative name server
  MD,         // a mail destination (Obsolete - use MX)
  MF,         // a mail forwarder (Obsolete - use MX)
  CNAME,      // the canonical name for an alias
  SOA,        // marks the start of a zone of authority
  MB,         // a mailbox domain name (EXPERIMENTAL)
  MG,         // a mail group member (EXPERIMENTAL)
  MR,         // a mail rename domain name (EXPERIMENTAL)
  NULL_,      // a null RR (EXPERIMENTAL)
  WKS,        // a well known service description
  PTR,        // a domain name pointer
  HINFO,      // host information
  MINFO,      // mailbox or mail list information
  MX,         // mail exchange
  TXT,        // text strings
  AAAA = 28,  // IPv6 address
  A6 = 38,
  Q_AXFR = 252,  // A request for a transfer of an entire zone
  Q_MAILB,       // A request for mailbox-related records (MB, MG or MR)
  Q_MAILA,       // A request for mail agent RRs (Obsolete - see MX)
  Q_ALL,         // A request for all records
};

enum class CLASS : int16_t {
  IN = 1,  // the Internet
  CS,  // the CSNET class (Obsolete - used only for examples in some obsolete
       // RFCs)
  CH,  // the CHAOS class
  HS,  // Hesiod [Dyer 87]
  Q_ALL = 255,  // any class
};

struct Question {
  std::string name;
  int16_t type;
  int16_t the_class;

  inline void reset() { name.clear(); }
};

struct ResourceRecord {
  std::string name;
  int16_t type;
  int16_t the_class;
  uint32_t ttl;
  std::vector<uint8_t> rdata;

  inline void reset() {
    name.clear();
    rdata.clear();
  }
};

struct Header {
  int16_t id;
  bool isQuery;
  int16_t operation;
  bool isAuthoritativeAnswer;
  bool isTruncated;
  bool isRecursionDesired;
  bool isRecursionAvailable;
  int16_t z;
  int16_t response_code;
};

struct Message {
  enum class Section {
    // custom enum, not part of rfc
    INVALID_VALUE,
    HEADER,
    QUESTION,
    ANSWER,
    AUTHORITY,
    ADDITIONAL,
  };
  Header header;
  std::vector<Question> questions;
  std::vector<ResourceRecord> answers;
  std::vector<ResourceRecord> authorities;
  std::vector<ResourceRecord> additional;
};

struct MessageView {
  size_t size;
  int16_t id;
  uint16_t answer_count;
  uint16_t authority_count;
  uint16_t additional_count;
  std::vector<size_t> question_offsets;
  std::vector<size_t> resource_record_offsets;
  void reset() {
    question_offsets.clear();
    resource_record_offsets.clear();
  }
};

}  // namespace dns
}  // namespace dnstoy
#endif  // DNSTOY_DNS_DEFINITION_H_