# tinyhttp
A tiny HTTP/1.1 server library, implemented with [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html) for networking and [io_submit](https://man7.org/linux/man-pages/man2/io_submit.2.html) for asynchronous file I/O.

Currently supported:

- [x] Accepting multiple connections at once
- [x] Basic header parsing
- [x] Utilities for reading specific headers (e.g. get the Content-Length)
- [x] Utilities for constructing HTTP responses
- [x] Transfer-Encoding: chunked responses
- [x] Transfer-Encoding: chunked requests
- [x] Low-level asynchronous file I/O
- [ ] Utilities for parsing parameters in the URL (e.g. /search?q=AAAAAA)
- [ ] Full RFC2616 Standard compliance

General todo list:

- [ ] Graceful shutdown, signal handling in general
- [ ] Syscall batching because context switching is expensive
