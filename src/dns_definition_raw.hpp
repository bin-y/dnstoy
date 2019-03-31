#ifndef DNSTOY_DNS_DEFINITION_RAW_H_
#define DNSTOY_DNS_DEFINITION_RAW_H_
#include <boost/endian/conversion.hpp>

namespace dnstoy {
namespace dns {
#pragma pack(push, 1)

struct RawTcpMessage {
  uint16_t message_length;
  uint8_t message[];
};

struct RawHeader {
#if BOOST_ENDIAN_BIG_BYTE
  struct Flag {
    static constexpr uint16_t QR_mask = 0b1000000000000000;
    static constexpr uint16_t QR_offset = 15;
    static constexpr uint16_t Opcode_mask = 0b0111100000000000;
    static constexpr uint16_t Opcode_offset = 11;
    static constexpr uint16_t AA_mask = 0b0000010000000000;
    static constexpr uint16_t AA_offset = 10;
    static constexpr uint16_t TC_mask = 0b0000001000000000;
    static constexpr uint16_t TC_offset = 9;
    static constexpr uint16_t RD_mask = 0b0000000100000000;
    static constexpr uint16_t RD_offset = 8;
    static constexpr uint16_t RA_mask = 0b0000000010000000;
    static constexpr uint16_t RA_offset = 7;
    static constexpr uint16_t Z_mask = 0b0000000001110000;
    static constexpr uint16_t Z_offset = 4;
    static constexpr uint16_t RCODE_mask = 0b0000000000001111;
    static constexpr uint16_t RCODE_offset = 0;
  };
#else
  struct Flag {
    static constexpr uint16_t QR_mask = 0b0000000010000000;
    static constexpr uint16_t QR_offset = 7;
    static constexpr uint16_t Opcode_mask = 0b0000000001111000;
    static constexpr uint16_t Opcode_offset = 3;
    static constexpr uint16_t AA_mask = 0b0000000000000100;
    static constexpr uint16_t AA_offset = 2;
    static constexpr uint16_t TC_mask = 0b0000000000000010;
    static constexpr uint16_t TC_offset = 1;
    static constexpr uint16_t RD_mask = 0b0000000000000001;
    static constexpr uint16_t RD_offset = 0;
    static constexpr uint16_t RA_mask = 0b1000000000000000;
    static constexpr uint16_t RA_offset = 15;
    static constexpr uint16_t Z_mask = 0b0111000000000000;
    static constexpr uint16_t Z_offset = 12;
    static constexpr uint16_t RCODE_mask = 0b0000111100000000;
    static constexpr uint16_t RCODE_offset = 8;
  };
#endif
  int16_t ID;
  uint16_t FLAGS;
  /* FLAGS:
    int8_t QR:1;
    int8_t Opcode:4;
    int8_t AA:1;
    int8_t TC:1;
    int8_t RD:1;
    int8_t RA:1;
    int8_t Z:3;
    int8_t RCODE:4;
    not using bit field because the order of allocation of bit-fields within a
    unit is implementation-defined.
  */
  uint16_t QDCOUNT;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
};

struct RawLabel {
  struct Flag {
    static constexpr uint8_t MASK =
        0b11000000;  // not a flag, flag value = (flag & MASK)
    static constexpr uint8_t NORMAL = 0b00000000;
    static constexpr uint8_t OFFSET = 0b11000000;
    static constexpr uint8_t RESERVED1 = 0b01000000;
    static constexpr uint8_t RESERVED2 = 0b10000000;
  };
  union {
    uint8_t flag;
    struct {
      uint8_t data_length;
      char data[];
    } normal_type;
    struct {
      uint8_t high_part_with_flag;
      uint8_t low_part;
    } offset_type;
  };
};

struct RawQuestion {
  RawLabel
      QNAME[1];  // 1 is not accurate, usually name contains more than one label
  uint16_t QTYPE;
  uint16_t QCLASS;
};

struct RawResourceRecord {
  RawLabel
      NAME[1];  // 1 is not accurate, usually name contains more than one label
  uint16_t TYPE;
  uint16_t CLASS;
  uint32_t TTL;
  uint16_t RDLENGTH;
  uint8_t RDATA[];
};

#pragma pack(pop)
}  // namespace dns
}  // namespace dnstoy
#endif  // DNSTOY_DNS_DEFINITION_RAW_H_