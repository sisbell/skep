# The suite's TLS fixtures

Two files, read by the suite's TLS front
(`tests/it/common/tls_front.rs`) and by nothing else:

- `tls-front-test-cert.pem` is one self-signed certificate for
  `localhost` and `127.0.0.1`, valid until 2126.
- `tls-front-test-key.pem` is its private key. It is a TEST key: it is
  public, here, on purpose, and it protects nothing. It signs the
  handshakes of the suite's own front on loopback and nothing else, and
  no build of any skep binary reads it.

The daemon serves plain HTTP; on a hosted board TLS is its proxy's. The
front stands where that proxy does, so a cell can reach a spawned daemon
over `https` (the resolver's mirror, `tests/it/resolve.rs`). No platform
trusts this certificate, so a dialer reaches the front only when a cell
hands it the certificate as its one test root
(`skep_client::dial::PlainHttp::trusting_test_root`, compiled under `tls`
and `test-hooks` together); the shipped dialer refuses it, which a cell
pins.

## How they were made

Once, on 2026-11-12, with OpenSSL 3.3.2, in this directory:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -keyout tls-front-test-key.pem -out tls-front-test-cert.pem \
  -sha256 -days 36500 -subj "/CN=skep suite TLS front (test only)" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
```

The key is ECDSA P-256 in PKCS#8, unencrypted (`-noenc`). The certificate
is both the leaf the front serves and the root a cell trusts, so it is no
CA (`CA:FALSE`): rustls's verifier, which judges it for the dialer that
holds the test root, takes no CA certificate as a leaf. A hundred years is
longer than Apple's trust policy lets a server certificate run: on macOS
the platform's verifier answers "certificate is not standards compliant",
with this certificate as an extra root as without it, so the dialer that
holds the test root asks no platform. Its SHA-256 fingerprint is

```text
8B:B1:F8:1C:D2:3D:D9:73:30:8A:09:56:57:47:67:0B:F3:C3:41:CB:E5:BD:8A:6D:02:A5:30:06:75:BC:83:6E
```

(`openssl x509 -in tls-front-test-cert.pem -noout -fingerprint -sha256`).
Running the command again makes a new pair; both files are then replaced
together, and nothing else names either.
