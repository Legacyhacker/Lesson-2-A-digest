# Lesson 2: A digest

The second lesson is about writing an engine with only a digest implementation

## Build

Build as follows:

    $ autoreconf -i
    $ ./configure
    $ make

A quick and easy test goes like this:

    $ OPENSSL_ENGINES=.libs openssl engine -t -c emd5

    $ echo whatever | OPENSSL_ENGINES=.libs openssl dgst -md5 -engine emd5


You may cross-check the result by using the openssl-internal MD5 implementation:

    $ echo whatever | openssl dgst -md5

