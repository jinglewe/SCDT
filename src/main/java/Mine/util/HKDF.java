package Mine.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HKDF {
    private static final String HMAC_ALGORITHM = "HmacSHA256"; // 使用HMAC-SHA256
    private final byte[] prk; // 伪随机密钥（PRK）
    public int keyLength;

    // 构造函数：Extract阶段
    public HKDF(byte[] ikm, byte[] salt) {
        try {
            // 如果盐值为空，使用全零的默认盐值
            if (salt == null || salt.length == 0) {
                salt = new byte[32]; // 32字节的全零盐值
            }

            // 使用HMAC-SHA256进行Extract
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(salt, HMAC_ALGORITHM);
            hmac.init(keySpec);
            this.prk = hmac.doFinal(ikm); // 生成PRK
            keyLength= prk.length;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HKDF extract failed", e);
        }
    }

    // Expand阶段：生成输出密钥
    public byte[] expand(byte[] info, int length) {
        try {
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(prk, HMAC_ALGORITHM);
            hmac.init(keySpec);

            byte[] result = new byte[length];
            byte[] t = new byte[0];
            int offset = 0;
            int i = 1;

            while (offset < length) {
                // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
                hmac.update(t);
                hmac.update(info);
                hmac.update((byte) i);
                t = hmac.doFinal();

                // 将T(i)复制到结果中
                int copyLength = Math.min(t.length, length - offset);
                System.arraycopy(t, 0, result, offset, copyLength);
                offset += copyLength;
                i++;
            }

            return result;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HKDF expand failed", e);
        }
    }

    // 生成两个与根密钥等长的输出
    public byte[][] expandToTwoOutputs(byte[] info) {
        int keyLength = prk.length; // 输出长度与PRK等长
        byte[] output = expand(info, 2*keyLength);
        byte[] output1 = Arrays.copyOfRange(output, 0, keyLength);
        byte[] output2 = Arrays.copyOfRange(output, keyLength, 2 * keyLength);
        return new byte[][]{output1, output2};
    }
}