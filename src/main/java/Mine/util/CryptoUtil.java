package Mine.util;

import Mine.UserSet;
import Mine.entity.*;
import it.unisa.dia.gas.jpbc.Element;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.SecureRandom;

public class CryptoUtil {
    /**
     * 获取哈希值
     *
     * @param mode    哈希模式
     * @param element 要哈希的值
     * @return 哈希过后的值
     */


    public static byte[] getHash(String mode, Element element) {
        byte[] hash_value = null;

        try {
            MessageDigest md = MessageDigest.getInstance(mode);
            hash_value = md.digest(element.toBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hash_value;
    }

    /**
     * 获取哈希值
     *
     * @param mode  哈希模式
     * @param bytes 要哈希的值
     * @return 哈希过后的值
     */
    public static byte[] getHash(String mode, byte[] bytes) {
        byte[] hash_value = null;

        try {
            MessageDigest md = MessageDigest.getInstance(mode);
            hash_value = md.digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hash_value;
    }

    /**
     * ElGamal加密函数
     *
     * @param key  加密密钥
     * @param data 要加密的数据
     * @return 密文
     */
    public static Element[] ElGamalEncrypt(Element p, Element key, Element data) {
        int k = new Random().nextInt();
        Element[] secret = new Element[2];

        secret[0] = p.duplicate().pow(BigInteger.valueOf(k));
        secret[1] = data.duplicate().add(key.duplicate().pow(BigInteger.valueOf(k)));

        return secret;

    }

    /**
     * ElGamal解密函数
     *
     * @param key  密钥
     * @param data 密文
     * @return 明文
     */
    public static Element ElGamalDecrypt(Element key, Element[] data) {
        return data[1].sub(data[0].mulZn(key));
    }

    /**
     * AES加密函数
     *
     * @param key  加密密钥,128或256位
     * @param data 要加密的数据
     * @return 密文
     */
    public static byte[] AESEncrypt(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Long begin = System.nanoTime();
        String key_algorithm = "AES";
        Cipher cipher;
        cipher = Cipher.getInstance("AES");
        Key key1 = initKeyForAES(new String(key));
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1.getEncoded(), key_algorithm));
        byte[] c = cipher.doFinal(data);
        Long end = System.nanoTime();
        System.out.println("Enc Time: " + (end-begin)*Math.pow(10,-6) + "ms");
        return c;
    }

    /**
     * AES解密函数
     *
     * @param key  密钥
     * @param data 密文
     * @return 明文
     */
    public static byte[] AESDecrypt(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Long begin = System.nanoTime();
        String key_algorithm = "AES";
        Cipher cipher;
        cipher = Cipher.getInstance("AES");
        Key key1 = initKeyForAES(new String(key));
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1.getEncoded(), key_algorithm));
        byte[] m = cipher.doFinal(data);
        Long end = System.nanoTime();
        System.out.println("Dec Time: " + (end-begin)*Math.pow(10,-6) + "ms");
        return m;
    }

    /**
     * X3DH通信连接建立函数
     * @param A 发送方
     * @param B 接收方
     * @return 连接参数实体，包括共享密钥SK，以及要发送给对方的临时公钥epk
     * @throws NoSuchAlgorithmException
     */
    public static connection x3dh(user A, user B) throws NoSuchAlgorithmException{
        connection conn = new connection();
        Element esk = UserSet.pairing.getZr().newRandomElement().getImmutable();
        conn.epk = UserSet.P_2.mulZn(esk).getImmutable();
        byte[] dh1 = B.spk.mulZn(A.isk).toBytes();
        byte[] dh2 = B.ipk.mulZn(esk).toBytes();
        byte[] dh3 = B.spk.mulZn(esk).toBytes();
        byte[] combined = new byte[dh1.length + dh2.length + dh3.length];
        System.arraycopy(dh1, 0, combined, 0, dh1.length);
        System.arraycopy(dh2, 0, combined, dh1.length, dh2.length);
        System.arraycopy(dh3, 0, combined, dh1.length + dh2.length, dh3.length);
        HKDF hkdf = new HKDF(combined,null);
        conn.SK = hkdf.expand("X3DH_Shared_Key".getBytes(), 32); // 生成 32 字节的共享密钥
        return conn;
    }
    public static connection x3dh(user A, user B, Element PK) throws NoSuchAlgorithmException{
        connection conn = new connection();
        byte[] dh1 = B.ipk.mulZn(A.ssk).toBytes();
        byte[] dh2 = PK.mulZn(A.isk).toBytes();
        byte[] dh3 = PK.mulZn(A.ssk).toBytes();
        byte[] combined = new byte[dh1.length + dh2.length + dh3.length];
        System.arraycopy(dh1, 0, combined, 0, dh1.length);
        System.arraycopy(dh2, 0, combined, dh1.length, dh2.length);
        System.arraycopy(dh3, 0, combined, dh1.length + dh2.length, dh3.length);
        HKDF hkdf = new HKDF(combined,null);
        conn.SK = hkdf.expand("X3DH_Shared_Key".getBytes(), 32); // 生成 32 字节的共享密钥
        conn.epk = null;
        return conn;
    }


    public static byte[] Derive(chains c){
        byte[] mk = null;

        if (c.dhOut != null) {
            System.out.println("DH Ratchet");
            HKDF hkdf = new HKDF(c.rk, c.dhOut.toBytes()); // 盐值可以为空
            byte[][] outputs = hkdf.expandToTwoOutputs("RootChainUpdate".getBytes());
            c.dhOut =  null;
            // 更新根密钥和链密钥
            c.rk = outputs[0]; // 第一个输出作为新的根密钥
            if (c.isSend) c.sendk = outputs[1];
            else c.recvkey = outputs[1];
        }
        if (c.isSend) {
            System.out.println("Send Ratchet");
//            Long Begin = System.nanoTime();
            HKDF sendChain = new HKDF(c.sendk,null);
            byte[][] sendOut = sendChain.expandToTwoOutputs("MessageChainUpdate".getBytes());
//            Long End = System.nanoTime();
//            System.out.println("hkdf Time:" + (End-Begin)*Math.pow(10,-6) + "ms");
            c.sendk = sendOut[0];
            mk = sendOut[1];
        } else {
            System.out.println("Recv Ratchet");
            HKDF recvChain = new HKDF(c.recvkey,null);
            byte[][] recvOut = recvChain.expandToTwoOutputs("MessageChainUpdate".getBytes());
            c.recvkey = recvOut[0];
            mk = recvOut[1];
        }
        return mk;
    }

    public static void dhRatchet(chains c){
        c.DHSendSk = UserSet.pairing.getZr().newRandomElement().getImmutable();
        c.DHSendPk = UserSet.P_2.mulZn(c.DHSendSk).getImmutable();
        c.dhOut = c.DHRecvPk.mulZn(c.DHSendSk);
    }
    public static void dhRatchet(chains c, boolean recv){
        c.dhOut = c.DHRecvPk.mulZn(c.DHSendSk);
    }

    public static ct DoubleRatchetEnc(byte[] plaintext, chains c, boolean stateTrans) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException{
        Long encBegin = System.nanoTime();
        c.isSend = true;
        if (stateTrans){dhRatchet(c);}
        byte[] mk = Derive(c);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128,new byte[12]);
        SecretKeySpec keySpec = new SecretKeySpec(mk,"AES");
        cipher.init(Cipher.ENCRYPT_MODE,keySpec,spec);
        byte[] AD = "dataTrans".getBytes();
        cipher.updateAAD(AD);
        ct cipherT = new ct();
        cipherT.cipherText = cipher.doFinal(plaintext);
        cipherT.PK = c.DHSendPk;
        Long encEnd = System.nanoTime();
        System.out.println("Enc1 Time:" + (encEnd-encBegin)*Math.pow(10,-6) + "ms");
        return cipherT;
    }

    public static byte[] DoubleRatchetDec(ct message, chains c, boolean stateTrans) throws Exception{
        Long decBegin = System.nanoTime();
        c.isSend = false;
        if(stateTrans){c.DHRecvPk = message.PK;dhRatchet(c,true);}
        byte[] AD = "dataTrans".getBytes();
        byte[] mk = Derive(c);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        SecretKeySpec keySpec = new SecretKeySpec(mk, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
        cipher.updateAAD(AD);
        byte[] plaintext = cipher.doFinal(message.cipherText);
        Long decEnd = System.nanoTime();
        System.out.println("Dec1 Time:" + (decEnd-decBegin)*Math.pow(10,-6) + "ms");
        return plaintext;
    }

    private static Key initKeyForAES(String key) throws NoSuchAlgorithmException {
        if (null == key || key.length() == 0) {
            throw new NullPointerException("key not is null");
        }
        SecretKeySpec key2;
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(key.getBytes());
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            key2 = new SecretKeySpec(enCodeFormat, "AES");
        } catch (NoSuchAlgorithmException ex) {
            throw new NoSuchAlgorithmException();
        }
        return key2;
    }


    public static ECPoint hashToP256(String input) throws NoSuchAlgorithmException {
        // Initialize Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Step 1: Hash the input using SHA-3
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            byte[] hash = digest.digest(input.getBytes());

            // Step 2: Map the hash to a point on the P-256 elliptic curve
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPoint point = mapToP256(hash, ecSpec);

            return point;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static ECPoint mapToP256(byte[] hash, ECParameterSpec ecSpec) {
        BigInteger x = new BigInteger(1, hash);

        // Ensure x is in the valid range for P-256
        x = x.mod(ecSpec.getN());

        // Use x-coordinate to generate the corresponding y-coordinate
        ECPoint point = ecSpec.getG().multiply(x).normalize();

        return point;
    }

    public static ECPoint scalarMultiply(BigInteger scalar, ECPoint point) {
        // Initialize Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Get the P-256 elliptic curve parameters
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

            // Perform scalar multiplication
            ECPoint result = point.multiply(scalar).normalize();

            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Element stringHashToG (String input, Field field, Pairing pairing) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(input.getBytes());

        // Map the hashed bytes to a field element
        Element fieldElement = field.newElementFromHash(hash, 0, hash.length).getImmutable();

        // Map the field element to a point on the elliptic curve
        Element resultElement = pairing.getG1().newElement().set(fieldElement).getImmutable();

        return resultElement;
    }
    public static BigInteger hashToZp(String input, BigInteger p) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(input.getBytes());
        BigInteger hashVal = new BigInteger(1, hashBytes);
        return hashVal.mod(p);

    }
}
