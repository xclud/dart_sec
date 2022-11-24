// ignore_for_file: non_constant_identifier_names

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'recovery.dart' as recovery;

/// Elliptic Curve.
class EC {
  const EC._(this._params);

  static final secp128r1 = EC._(ECCurve_secp128r1());
  static final secp128r2 = EC._(ECCurve_secp128r2());
  static final secp160k1 = EC._(ECCurve_secp160k1());
  static final secp160r1 = EC._(ECCurve_secp160r1());
  static final secp160r2 = EC._(ECCurve_secp160r2());
  static final secp192k1 = EC._(ECCurve_secp192k1());
  static final secp192r1 = EC._(ECCurve_secp192r1());
  static final secp224k1 = EC._(ECCurve_secp224k1());
  static final secp224r1 = EC._(ECCurve_secp224r1());
  static final secp256k1 = EC._(ECCurve_secp256k1());
  static final secp256r1 = EC._(ECCurve_secp256r1());
  static final secp384r1 = EC._(ECCurve_secp384r1());
  static final secp521r1 = EC._(ECCurve_secp521r1());
  static final brainpoolp160r1 = EC._(ECCurve_brainpoolp160r1());
  static final brainpoolp160t1 = EC._(ECCurve_brainpoolp160t1());
  static final brainpoolp192r1 = EC._(ECCurve_brainpoolp192r1());
  static final brainpoolp192t1 = EC._(ECCurve_brainpoolp192t1());
  static final brainpoolp224r1 = EC._(ECCurve_brainpoolp224r1());
  static final brainpoolp224t1 = EC._(ECCurve_brainpoolp224t1());
  static final brainpoolp256r1 = EC._(ECCurve_brainpoolp256r1());
  static final brainpoolp256t1 = EC._(ECCurve_brainpoolp256t1());
  static final brainpoolp320r1 = EC._(ECCurve_brainpoolp320r1());
  static final brainpoolp320t1 = EC._(ECCurve_brainpoolp320t1());
  static final brainpoolp384r1 = EC._(ECCurve_brainpoolp384r1());
  static final brainpoolp384t1 = EC._(ECCurve_brainpoolp384t1());
  static final brainpoolp512r1 = EC._(ECCurve_brainpoolp512r1());
  static final brainpoolp512t1 = EC._(ECCurve_brainpoolp512t1());
  static final gostr3410_2001_cryptopro_a =
      EC._(ECCurve_gostr3410_2001_cryptopro_a());
  static final gostr3410_2001_cryptopro_b =
      EC._(ECCurve_gostr3410_2001_cryptopro_b());
  static final gostr3410_2001_cryptopro_c =
      EC._(ECCurve_gostr3410_2001_cryptopro_c());
  static final gostr3410_2001_cryptopro_xcha =
      EC._(ECCurve_gostr3410_2001_cryptopro_xcha());
  static final gostr3410_2001_cryptopro_xchb =
      EC._(ECCurve_gostr3410_2001_cryptopro_xchb());
  static final prime192v1 = EC._(ECCurve_prime192v1());
  static final prime192v2 = EC._(ECCurve_prime192v2());
  static final prime192v3 = EC._(ECCurve_prime192v3());
  static final prime239v1 = EC._(ECCurve_prime239v1());
  static final prime239v2 = EC._(ECCurve_prime239v2());
  static final prime239v3 = EC._(ECCurve_prime239v3());
  static final prime256v1 = EC._(ECCurve_prime256v1());
  static final secp112r1 = EC._(ECCurve_secp112r1());
  static final secp112r2 = EC._(ECCurve_secp112r2());

  final ECDomainParameters _params;

  /// Creates a Public Key from the given Private Key.
  Uint8List createPublicKey(BigInt privateKey, bool compressed) {
    final q = _params.G * privateKey;

    return q!.getEncoded(compressed);
  }

  /// Generates a Digital Signature.
  ECSignature generateSignature(BigInt privateKey, Uint8List message,
      [bool makeCanonical = true]) {
    var signer = ECDSASigner();

    var priv = PrivateKeyParameter(ECPrivateKey(privateKey, _params));

    final sGen = Random.secure();
    var ran = SecureRandom('Fortuna');
    ran.seed(KeyParameter(
        Uint8List.fromList(List.generate(32, (_) => sGen.nextInt(255)))));

    signer.init(true, ParametersWithRandom(priv, ran));
    var rs = signer.generateSignature(message);
    final signature = rs as ECSignature;

    if (makeCanonical) {
      final canonical = signature.normalize(_params);

      return canonical;
    } else {
      return signature;
    }
  }

  /// Verifies a Digital Signature.
  bool verifySignature(
      Uint8List publicKey, Uint8List message, ECSignature signature) {
    var signer = ECDSASigner();

    var q = _params.curve.decodePoint(publicKey);
    var pub = PublicKeyParameter(ECPublicKey(q, _params));
    signer.init(false, pub);

    var result = signer.verifySignature(message, signature);
    return result;
  }

  /// Calculates Recovery Id for the Public Key and Message.
  int? calculateRecoveryId(
    BigInt publicKey,
    ECSignature signature,
    Uint8List message,
  ) {
    return recovery.calculateRecoveryId(publicKey, signature, message, _params);
  }
}
