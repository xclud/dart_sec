import 'package:convert/convert.dart';
import 'package:sec/sec.dart';

void main() {
  final privateKey = BigInt.parse(
    'c57304b3a53051600d7035fc593083810a8fa250e6a7a2803cf6a0f3c2750503',
    radix: 16,
  );

  final publicKey = Secp256k1.createPublicKey(privateKey, true);
  final pkHex = hex.encode(publicKey);
  print('Public Key: $pkHex');

  // 03566b04ce8459c8e2f95691ff17625a0b84773ecd2b65f597c05bd90fa8609ed6
}
