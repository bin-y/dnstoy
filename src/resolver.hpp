#ifndef DNSTOY_RESOLVER_H_
#define DNSTOY_RESOLVER_H_

#include "query.hpp"
#include "tls_resolver.hpp"

namespace dnstoy {

class Resolver {
 public:
  static int init();
  static void Resolve(QueryContext::weak_pointer query);
};

}  // namespace dnstoy
#endif  // DNSTOY_RESOLVER_H_