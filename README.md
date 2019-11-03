# dnstoy [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/bin-y/dnstoy.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bin-y/dnstoy/context:cpp) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/6a0ac951eb384297b29ca2c4be1059a8)](https://www.codacy.com/app/bin-y/dnstoy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=bin-y/dnstoy&amp;utm_campaign=Badge_Grade)
a lightweight dns-over-tls proxy (WIP)

## Project status
Not ready for production

## TODO
  - [x] Basic functionality (accept query from UDP/TCP client -> resolve query through dns-over-tls protocol -> forward answer to user)
  - [x] Reuse connection to prevent unnecessary tls handshake
  - [x] Response time based load balancing
  - [x] Parallel resolve all queries
  - [x] Resolve query via mutliple remote servers (when under light load)
  - [x] SSL session cache
  - [ ] [rfc7828 The edns-tcp-keepalive EDNS0 Option](https://tools.ietf.org/html/rfc7828)
  - [ ] [rfc7871 Client Subnet in DNS Queries](https://tools.ietf.org/html/rfc7871)
  - [ ] [rfc7830 The EDNS(0) Padding Option](https://tools.ietf.org/html/rfc7830)
  - [ ] Cache
  - [ ] Support TCP/UDP foreign server
  - [ ] Select foreign server by rule

## Know more about dns-over-tls
<https://en.wikipedia.org/wiki/DNS_over_TLS>

<https://developers.cloudflare.com/1.1.1.1/dns-over-tls/>

<https://developers.google.com/speed/public-dns/docs/dns-over-tls>
