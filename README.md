[![package publisher](https://img.shields.io/pub/publisher/sec.svg)](https://pub.dev/packages/sec/publisher)

Implementation of `Standards for Efficient Cryptography (SEC)` including SECP256K1 and SECP256R1.

## Features

* PublicKey Recovery Id Calculation.
* Secp160r1
* Secp160r2
* Secp192k1
* Secp192r1
* Secp224k1
* Secp224r1
* Secp256k1 (Commonly used in cryptocurrencies)
* Secp256r1
* Secp384r1
* Secp521r1
* Brainpoolp160r1
* Brainpoolp160t1
* Brainpoolp192r1
* Brainpoolp192t1
* Brainpoolp224r1
* Brainpoolp224t1
* Brainpoolp256r1
* Brainpoolp256t1
* Brainpoolp320r1
* Brainpoolp320t1
* Brainpoolp384r1
* Brainpoolp384t1
* Brainpoolp512r1
* Brainpoolp512t1
* Gostr3410_2001_cryptopro_a
* Gostr3410_2001_cryptopro_b
* Gostr3410_2001_cryptopro_c
* Gostr3410_2001_cryptopro_xcha
* Gostr3410_2001_cryptopro_xchb
* Prime192v1
* Prime192v2
* Prime192v3
* Prime239v1
* Prime239v2
* Prime239v3
* Prime256v1
* Secp112r1
* Secp112r2
* Secp128r1
* Secp128r2
* Secp160k1

## Getting started

```yaml
dependencies:
  sec: any
```

## Usage

```dart
import 'package:sec/sec.dart';
import 'package:convert/convert.dart';
```

```dart
final privateKey = BigInt.parse(
'c57304b3a53051600d7035fc593083810a8fa250e6a7a2803cf6a0f3c2750503',
radix: 16,
);

final publicKey = Secp256k1.createPublicKey(privateKey, true);
final pkHex = hex.encode(publicKey);
print('Public Key: $pkHex');

// 03566b04ce8459c8e2f95691ff17625a0b84773ecd2b65f597c05bd90fa8609ed6
```

## Additional information

This package uses [pointycastle](https://pub.dev/packages/pointycastle).
