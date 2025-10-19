package Mine.util;

import Mine.entity.BlockData;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;

public class StringUtil {
    // 应用SHA256算法生成哈希值
    public static String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static byte[] BlockDataToByte(BlockData bd) throws IOException {
        byte[][] datas = new byte[][]{bd.cbsk,bd.cisk, bd.ipk};
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] arr : datas) {
            outputStream.write(arr);
        }
        return outputStream.toByteArray();
    }
    public static String bytesToHex(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b)); // 每个字节转换为两位十六进制
        }
        return sb.toString();
    }
}
