package Mine;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class BlindECDSA {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 椭圆曲线参数
    private static final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final BigInteger n = ecSpec.getN(); // 曲线阶数

    // 生成密钥对
    public static AsymmetricCipherKeyPair generateKeyPair() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECDomainParameters domainParams = new ECDomainParameters(
                ecSpec.getCurve(),
                ecSpec.getG(),
                ecSpec.getN(),
                ecSpec.getH(),
                ecSpec.getSeed()
        );
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
        generator.init(keyGenParams);
        return generator.generateKeyPair();
    }

    // 盲化消息
    public static ECPoint blindMessage(String message, BigInteger alpha, BigInteger beta, ECPoint publicKeyPoint) {
        BigInteger messageHash = hashMessage(message);
        BigInteger alphaInverse = alpha.modInverse(n);
        ECPoint mBlind = ecSpec.getG().multiply(messageHash.multiply(alphaInverse).mod(n))
                .add(publicKeyPoint.multiply(beta));
        return mBlind;
    }

    // 签名盲化消息（使用 ECDSASigner）
    public static BigInteger[] signBlindMessage(ECPoint mBlind, ECPrivateKeyParameters privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ParametersWithRandom(privateKey, new SecureRandom()));
        BigInteger[] signature = signer.generateSignature(hashPoint(mBlind).toByteArray());
        return signature;
    }

    // 去盲化签名
    public static BigInteger[] unblindSignature(BigInteger[] blindSignature, BigInteger alpha, BigInteger beta) {
        BigInteger r = blindSignature[0];
        BigInteger s = blindSignature[1];
        BigInteger sUnblind = s.multiply(alpha).add(beta).mod(n);
        return new BigInteger[]{r, sUnblind};
    }

    // 验证签名（使用 ECDSASigner）
    public static boolean verifySignature(String message, BigInteger[] signature, ECPublicKeyParameters publicKey) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKey);
        BigInteger messageHash = hashMessage(message);
        return signer.verifySignature(messageHash.toByteArray(), signature[0], signature[1]);
    }

    // 计算消息哈希
    private static BigInteger hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes());
            return new BigInteger(1, hash).mod(n);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // 计算椭圆曲线点的哈希
    private static BigInteger hashPoint(ECPoint point) {
        byte[] encoded = point.getEncoded(false);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(encoded);
            return new BigInteger(1, hash).mod(n);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 生成密钥对
        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        System.out.println(privateKey);
        System.out.println(publicKey);
//
//        // 用户盲化消息
//        String message = "123";
//        BigInteger alpha = new BigInteger(n.bitLength(), new SecureRandom()).mod(n);
//        BigInteger beta = new BigInteger(n.bitLength(), new SecureRandom()).mod(n);
//        ECPoint mBlind = blindMessage(message, alpha, beta, publicKey.getQ());
//
//        // 签名者签名盲化消息
//        BigInteger[] blindSignature = signBlindMessage(mBlind, privateKey);
//
//        // 用户去盲化
//        BigInteger[] signature = unblindSignature(blindSignature, alpha, beta);
//
////         验证签名
//        boolean isValid = verifySignature(message, signature, publicKey);

//             非盲化ECDSA签名
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String message = "123";
        byte[] hash = digest.digest(message.getBytes());
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ParametersWithRandom(privateKey, new SecureRandom()));
        BigInteger[] Sig = signer.generateSignature(hash);
        ECDSASigner signerVrfy = new ECDSASigner();
        signerVrfy.init(false, publicKey);
        boolean isValid = signerVrfy.verifySignature(hash, Sig[0], Sig[1]);
        System.out.println("Signature is valid: " + isValid);
    }
}