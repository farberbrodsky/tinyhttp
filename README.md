# tinyhttp
A tiny HTTP/1.1 server library, implemented with [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html).

Currently supported:

- [x] Accepting multiple connections at once
- [x] Basic header parsing
- [ ] Utilities for reading specific headers (e.g. get the Content-Length)
- [ ] Utilities for constructing HTTP responses
- [ ] Utilities for parsing parameters in the URL (e.g. /search?q=AAAAAA)
- [ ] Transfer-Encoding: chunked responses and requests
- [ ] Full RFC2616 Standard compliance
