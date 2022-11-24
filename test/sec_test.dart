import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart';
import 'package:sec/sec.dart';
import 'package:test/test.dart';
import 'package:pointycastle/src/utils.dart' as utils;

void main() {
  group('SECP256K1', () {
    final privateKey = BigInt.parse(
      '891a19ddf98215bd4270fdbd3d6b1f82af9bb7ffb439ee981c19180abc9f1645',
      radix: 16,
    );

    final publicKey = Secp256k1.createPublicKey(privateKey, true);
    final pkHex = hex.encode(publicKey);

    test('Compressed Public Key', () {
      expect(
        pkHex,
        '030c25a7b90a6d9a76085415718b10dc3fccaeeda250b3f2dfa0b23947f60d8811',
      );
    });
  });

  test('Tron transaction signature verification.', () {
    final sk = BigInt.parse(
        'c57304b3a53051600d7035fc593083810a8fa250e6a7a2803cf6a0f3c2750503',
        radix: 16);

    final pk = Secp256k1.createPublicKey(sk, false);
    final pkInt = utils.decodeBigIntWithSign(1, pk.sublist(1));
    final message = Uint8List.fromList(hex.decode(
        '491c81e567b1cc3194e3c573fb433546b4f51c8ad7a363e7dfbbaea78d26aedc'));

    final hash = SHA256Digest().process(message);
    final sign = Secp256k1.generateSignature(sk, hash);
    final recId = Secp256k1.calculateRecoveryId(pkInt, sign, hash)! + 27;

    final signature = Secp256k1.generateSignature(sk, message, false);

    final rHex = signature.r.toRadixString(16).padLeft(64, '0');
    final sHex = signature.s.toRadixString(16).padLeft(64, '0');
    final recHex = recId.toRadixString(16).padLeft(2, '0');

    final txSig = '$rHex$sHex$recHex';

    print(txSig);
  });
}
