# pt-aes

C11 implementations and minimal test suite of the following AES key
lengths and block modes:

* AES-128-ECB
* AES-192-ECB
* AES-256-ECB
* AES-128-CBC
* AES-192-CBC
* AES-256-CBC
* AES-128-CTR

Implementation based on [FIPS-197][].

**Note**: This AES implementation is vulnerable cache timing attacks; do
not use it on a live system.

* [FIPS-197]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
