Implementation of `Standards for Efficient Cryptograph (SEC)` including SECP256K1 and SECP256R1.

## Features

* Secp256K1
* Secp256R1
* PublicKey Recovery Id Calculation.

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

This package uses [pointycastle](https://pub.dev/packages/point).
