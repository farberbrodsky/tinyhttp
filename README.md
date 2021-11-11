# tinyhttp
A tiny HTTP/1.1 server library, implemented with [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html).

Currently supported:

- [x] Accepting multiple connections at once
- [x] Basic header parsing
- [x] Utilities for reading specific headers (e.g. get the Content-Length)
- [x] Utilities for constructing HTTP responses
- [x] Transfer-Encoding: chunked responses
- [x] Transfer-Encoding: chunked requests
- [ ] Utilities for parsing parameters in the URL (e.g. /search?q=AAAAAA)
- [ ] Full RFC2616 Standard compliance

It is mostly single-threaded, but since you can't use epoll to read normal files (man epoll_ctl, errors, EPERM), I have to use a separate thread for most file IO operations. This is not yet implemented.
