# Recorded TLS sessions

Each `<name>.c2s.bin` / `<name>.s2c.bin` pair is the raw byte stream of one
direction of a loopback TLS connection between `openssl s_client` and
`openssl s_server -rev` (OpenSSL 3.0.13), and `<name>.keylog` is the client's
`-keylogfile`. The client sends `hello-device`; the server answers with the
line reversed. They cover suites and behaviour Go's `crypto/tls` cannot
produce, so the decryptor is checked against an independent implementation.

| Name | Negotiated |
|---|---|
| `dhe-gcm` | TLS 1.2 `DHE-RSA-AES256-GCM-SHA384` |
| `dhe-chacha` | TLS 1.2 `DHE-RSA-CHACHA20-POLY1305` |
| `dhe-cbc-sha` | TLS 1.2 `DHE-RSA-AES128-SHA`, MAC-then-encrypt |
| `cbc384-mte` | TLS 1.2 `ECDHE-RSA-AES256-SHA384`, MAC-then-encrypt (`-no_etm` on the server) |
| `cbc384-etm` | TLS 1.2 `ECDHE-RSA-AES256-SHA384`, encrypt-then-MAC |
| `keyupdate` | TLS 1.3; the client sends `before-update`, a KeyUpdate that requests one in return, then `after-update` |

The certificate and every secret here were generated for these recordings and
protect nothing.
