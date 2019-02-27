# dnstoy
a lightweight dns-to-tls proxy (WIP)

## Project status
Not ready for production

## TODO:
- [x] Basic function (accept query from UDP/TCP -> forward query to dns-over-tls server -> forward answer to user)
- [x] One tls connection for multiple queries
- [ ] [DANE for foreign server](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities)
- [ ] [rfc7828 The edns-tcp-keepalive EDNS0 Option](https://tools.ietf.org/html/rfc7828)
- [ ] [rfc7871 Client Subnet in DNS Queries](https://tools.ietf.org/html/rfc7828)
- [ ] [rfc7830 The EDNS(0) Padding Option](https://tools.ietf.org/html/rfc7830)
- [ ] Cache
- [ ] Support TCP/UDP foreign server
- [ ] Select foreign server by rule
- [ ] Detect fastest server

## Knowmore about dns-over-tls
https://en.wikipedia.org/wiki/DNS_over_TLS

https://developers.cloudflare.com/1.1.1.1/dns-over-tls/

https://developers.google.com/speed/public-dns/docs/dns-over-tls
