package Mine;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.protocol.*;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class SignalFileEncryptionExample {

    public static void main(String[] args) throws Exception {
        // 1. 生成身份密钥对
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();

        // 2. 生成注册 ID
        int registrationId = KeyHelper.generateRegistrationId(false);

        // 3. 生成预密钥
        int preKeyStartId = 1; // 预密钥的起始 ID
        int preKeyCount = 100; // 生成的预密钥数量
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(preKeyStartId, preKeyCount);

        // 4. 生成签名预密钥
        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, 1);

        // 5. 初始化存储
        SignalProtocolStore store = new InMemorySignalProtocolStore(identityKeyPair, registrationId);

        // 6. 存储预密钥
        for (PreKeyRecord preKey : preKeys) {
            store.storePreKey(preKey.getId(), preKey);
        }

        // 7. 存储签名预密钥
        store.storeSignedPreKey(signedPreKey.getId(), signedPreKey);

        // 8. 创建用户地址
        SignalProtocolAddress aliceAddress = new SignalProtocolAddress("alice", 1);
        SignalProtocolAddress bobAddress = new SignalProtocolAddress("bob", 1);

        // 9. 创建 PreKeyBundle
        PreKeyBundle preKeyBundle = new PreKeyBundle(
                registrationId, // 注册 ID
                bobAddress.getDeviceId(), // 设备 ID
                preKeys.get(0).getId(), // 预密钥 ID
                preKeys.get(0).getKeyPair().getPublicKey(), // 预密钥公钥
                signedPreKey.getId(), // 签名预密钥 ID
                signedPreKey.getKeyPair().getPublicKey(), // 签名预密钥公钥
                signedPreKey.getSignature(), // 签名
                identityKeyPair.getPublicKey() // 身份公钥
        );

        // 10. 初始化会话
        SessionBuilder aliceSessionBuilder = new SessionBuilder(store, bobAddress);
        aliceSessionBuilder.process(preKeyBundle); // 使用 PreKeyBundle 初始化会话

        // 11. 创建 10MB 数据文件
        String inputFilePath = "10MB_data.txt";
        String encryptedFilePath = "10MB_encrypted.bin";
        String decryptedFilePath = "10MB_decrypted.txt";

        create10MBFile(inputFilePath); // 创建 10MB 文件
        System.out.println("10MB 文件已创建: " + inputFilePath);

        // 12. 读取文件内容
        Long EncStartTime = System.nanoTime();
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFilePath));
        System.out.println("加密内容，大小: " + fileContent.length + " 字节");
//        System.out.printf("文件内容已读取，大小: %.2f KB" , len);
//        System.out.println("加密内容，大小: " + "hello".getBytes().length + " 字节");

        // 13. 加密文件内容
        SessionCipher aliceSessionCipher = new SessionCipher(store, bobAddress);
        CiphertextMessage encryptedMessage = aliceSessionCipher.encrypt(fileContent);

        // 14. 将加密后的数据写入文件
        byte[] encryptedMessageBytes = encryptedMessage.serialize();
//        String str = new String(encryptedMessageBytes, java.nio.charset.StandardCharsets.UTF_8);
//        System.out.println(str);
        Files.write(Paths.get(encryptedFilePath), encryptedMessageBytes);
        System.out.println("文件内容已加密并保存到: " + encryptedFilePath);
        Long EncEndTime = System.nanoTime();
        System.out.println("Enc Time:" + (EncEndTime-EncStartTime) +"ns");
        byte[] EncfileContent = Files.readAllBytes(Paths.get(encryptedFilePath));
        System.out.println("加密文件内容已读取，大小: " + EncfileContent.length + " 字节");

        // 15. 解密文件内容
        Long DecStartTime = System.nanoTime();
        SessionCipher bobSessionCipher = new SessionCipher(store, aliceAddress);
        byte[] decryptedMessage = bobSessionCipher.decrypt(new PreKeySignalMessage(encryptedMessageBytes));

        // 16. 将解密后的数据写入文件
        Files.write(Paths.get(decryptedFilePath), decryptedMessage);
        System.out.println("文件内容已解密并保存到: " + decryptedFilePath);
        Long DecEndTime = System.nanoTime();
        System.out.println("Enc Time:" + (DecEndTime-DecStartTime)+"ns");

// 17. 验证解密后的文件是否与原始文件一致
        if (compareFiles(inputFilePath, decryptedFilePath)) {
            System.out.println("解密成功！解密后的文件与原始文件一致。");
        } else {
            System.out.println("解密失败！解密后的文件与原始文件不一致。");
        }
    }

    /**
     * 创建一个 10MB 的文件。
     *
     * @param filePath 文件路径
     * @throws IOException 如果文件创建失败
     */
    private static void create10MBFile(String filePath) throws IOException {
        int fileSize = 10 * 1024 *1024 ; // 10MB
        byte[] data = new byte[fileSize];
        for (int i = 0; i < fileSize; i++) {
            data[i] = (byte) (i % 256); // 填充数据
        }
        Files.write(Paths.get(filePath), data);
    }
    private static boolean compareFiles(String filePath1, String filePath2) throws IOException {
        try (BufferedInputStream input1 = new BufferedInputStream(new FileInputStream(filePath1));
             BufferedInputStream input2 = new BufferedInputStream(new FileInputStream(filePath2))) {
            int byte1, byte2;
            while ((byte1 = input1.read()) != -1 && (byte2 = input2.read()) != -1) {
                if (byte1 != byte2) {
                    return false;
                }
            }
            // 检查文件长度是否一致
            return input1.read() == -1 && input2.read() == -1;
        }
    }
}
