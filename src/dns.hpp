#ifndef DNSTOY_DNS_H_
#define DNSTOY_DNS_H_

#include "dns_definition.hpp"
#include "dns_message_decoder.hpp"
#include "dns_message_encoder.hpp"

namespace dns {

struct TransportTypeFlags {
  static constexpr uintptr_t UDP = 1 << 0;
  static constexpr uintptr_t TCP = 1 << 1;
  static constexpr uintptr_t HTTPS = 1 << 2;
  static constexpr uintptr_t TLS = 1 << 3;
};

}  // namespace dns

#endif  // DNSTOY_DNS_H_