import 'dart:typed_data';

import 'package:pointycastle/export.dart' as p;
import 'recovery.dart' as recovery;

final _domainParams = p.ECCurve_secp256r1();

/// Secp256r1
class Secp256r1 {
  Secp256r1._();

  /// EC Domain Parameters.
  static p.ECDomainParameters get domainParams => _domainParams;

  /// Creates a Public Key from the given Private Key.
  static Uint8List createPublicKey(BigInt privateKey, bool compressed) {
    final q = _domainParams.G * privateKey;

    final publicParams = p.ECPublicKey(q, _domainParams);

    return publicParams.Q!.getEncoded(compressed);
  }

  /// Generates a Digital Signature.
  static p.ECSignature generateSignature(BigInt privateKey, Uint8List message,
      [bool makeCanonical = true]) {
    var signer = p.ECDSASigner();

    var priv = p.PrivateKeyParameter(p.ECPrivateKey(privateKey, _domainParams));
    signer.init(true, priv);
    var rs = signer.generateSignature(message);

    final signature = rs as p.ECSignature;

    if (makeCanonical) {
      final canonical = signature.normalize(_domainParams);

      return canonical;
    } else {
      return signature;
    }
  }

  /// Verifies a Digital Signature.
  static bool verifySignature(
    Uint8List publicKey,
    Uint8List message,
    p.ECSignature signature,
  ) {
    var signer = p.ECDSASigner();

    var q = _domainParams.curve.decodePoint(publicKey);
    var pub = p.PublicKeyParameter(p.ECPublicKey(q, _domainParams));
    signer.init(false, pub);

    var result = signer.verifySignature(message, signature);
    return result;
  }

  /// Calculates Recovery Id for the Public Key and Message.
  static int? calculateRecoveryId(
    BigInt publicKey,
    p.ECSignature signature,
    Uint8List message,
  ) {
    return recovery.calculateRecoveryId(
        publicKey, signature, message, _domainParams);
  }
}
