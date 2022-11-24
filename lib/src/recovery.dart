import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/export.dart' as p;
// ignore: implementation_imports
import 'package:pointycastle/src/utils.dart' as utils;

/// Calculates Recovery Id for the Public Key and Message.
int? calculateRecoveryId(
  BigInt publicKey,
  p.ECSignature signature,
  Uint8List message,
  ECDomainParameters params,
) {
  for (var i = 0; i < 4; i++) {
    final k = _recoverFromSignature(i, signature, message, params);
    if (k == publicKey) {
      return i;
    }
  }

  return null;
}

BigInt? _recoverFromSignature(
  int recId,
  p.ECSignature sig,
  Uint8List msg,
  p.ECDomainParameters params,
) {
  final n = params.n;
  final i = BigInt.from(recId ~/ 2);
  final x = sig.r + (i * n);

  //Parameter q of curve
  final prime = BigInt.parse(
    'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
    radix: 16,
  );
  if (x.compareTo(prime) >= 0) return null;

  final R = _decompressKey(x, (recId & 1) == 1, params.curve);
  if (!(R * n)!.isInfinity) return null;

  final e = utils.decodeBigIntWithSign(1, msg);

  final eInv = (BigInt.zero - e) % n;
  final rInv = sig.r.modInverse(n);
  final srInv = (rInv * sig.s) % n;
  final eInvrInv = (rInv * eInv) % n;

  final q = (params.G * eInvrInv)! + (R * srInv);

  final bytes = q!.getEncoded(false);
  return utils.decodeBigIntWithSign(1, bytes.sublist(1));
}

p.ECPoint _decompressKey(BigInt xBN, bool yBit, p.ECCurve c) {
  List<int> x9IntegerToBytes(BigInt s, int qLength) {
    //https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/x9/X9IntegerConverter.java#L45
    final bytes = utils.encodeBigInt(s);

    if (qLength < bytes.length) {
      return bytes.sublist(0, bytes.length - qLength);
    } else if (qLength > bytes.length) {
      final tmp = List<int>.filled(qLength, 0);

      final offset = qLength - bytes.length;
      for (var i = 0; i < bytes.length; i++) {
        tmp[i + offset] = bytes[i];
      }

      return tmp;
    }

    return bytes;
  }

  final compEnc = x9IntegerToBytes(xBN, 1 + ((c.fieldSize + 7) ~/ 8));
  compEnc[0] = yBit ? 0x03 : 0x02;
  return c.decodePoint(compEnc)!;
}
