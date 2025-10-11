package Mine;

import Mine.entity.*;
import Mine.util.CryptoUtil;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.sql.SQLOutput;
import java.util.Arrays;

public class DataTrans {
    public static void main(String[] args) throws Exception {
        user alice = new user(); //sender
        user bob = new user();  //receiver
        UserSet.Init(alice);
        UserSet.Init(bob);
        Long x3dhBegin = System.nanoTime();
        connection aliceSK = CryptoUtil.x3dh(alice,bob);
        Long x3dhEnd = System.nanoTime();
        System.out.println("x3dh:" + (x3dhEnd-x3dhBegin));
        System.out.println(aliceSK.epk.toBytes().length);
        chains aliceChains = new chains(aliceSK.SK,true);
        aliceChains.DHRecvPk = bob.spk;
        alice.c = aliceChains;
        UserSet.ChainInit(alice);
        connection bobSK = CryptoUtil.x3dh(bob,alice,aliceSK.epk);
        bob.c = new chains(bobSK.SK,false);
        UserSet.ChainInit(bob);
        boolean isequ = Arrays.equals(aliceSK.SK,bobSK.SK);
        System.out.println("SK:" + isequ);

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
        //上述初始化链已完成，现Alice发送消息
        ct ciphert = CryptoUtil.DoubleRatchetEnc(fileContent,alice.c,false);
        // 14. 将加密后的数据写入文件
        Files.write(Paths.get(encryptedFilePath), ciphert.cipherText);
        System.out.println("文件内容已加密并保存到: " + encryptedFilePath);
        byte[] EncfileContent = Files.readAllBytes(Paths.get(encryptedFilePath));
        System.out.println("加密文件内容已读取，大小: " + (EncfileContent.length+ciphert.PK.getLengthInBytes()) + " 字节");


        bob.c.DHRecvPk = ciphert.PK;
        CryptoUtil.dhRatchet(bob.c,true);
        byte[] pt = CryptoUtil.DoubleRatchetDec(ciphert,bob.c,false);
        // 16. 将解密后的数据写入文件
        Files.write(Paths.get(decryptedFilePath), pt);
        // 17. 验证解密后的文件是否与原始文件一致
        if (compareFiles(inputFilePath, decryptedFilePath)) {
            System.out.println("解密成功！解密后的文件与原始文件一致。");
        } else {
            System.out.println("解密失败！解密后的文件与原始文件不一致。");
        }

//        System.out.println(new String(pt));
        System.out.println("\n");
        System.out.println("external size:" + ((EncfileContent.length+ciphert.PK.getLengthInBytes())-fileContent.length));
        System.out.println("external size:" + (EncfileContent.length-fileContent.length));

        //接收双方身份转变，现bob发送消息，那么首先bob需要进行dh棘轮，再更新发送链
        System.out.println("2");
        ct ciphert_2 = CryptoUtil.DoubleRatchetEnc(fileContent,bob.c,true);
        byte[] pt_2 = CryptoUtil.DoubleRatchetDec(ciphert_2,alice.c,true);
//        System.out.println(new String(pt_2));
        System.out.println("\n");
//
        //bob继续发送消息
        System.out.println("3");
        ct ciphert_3 = CryptoUtil.DoubleRatchetEnc(fileContent,bob.c,false);
        byte[] pt_3 = CryptoUtil.DoubleRatchetDec(ciphert_3,alice.c,false);
//        System.out.println(new String(pt_3));
        System.out.println("\n");
//
//        //bob继续发送消息
//        ct ciphert_4 = CryptoUtil.DoubleRatchetEnc(fileContent,bob.c,false);
//        byte[] pt_4 = CryptoUtil.DoubleRatchetDec(ciphert_4,alice.c,false);
////        System.out.println(new String(pt_4));
//        System.out.println("\n");
//
//        //接收双方身份转变，现alice发送消息，那么首先alice需要进行dh棘轮，再更新发送链
//        ct ciphert_5 = CryptoUtil.DoubleRatchetEnc(fileContent,alice.c,true);
//        byte[] pt_5 = CryptoUtil.DoubleRatchetDec(ciphert_5,bob.c,true);
////        System.out.println(new String(pt_5));
//        System.out.println("\n");
    }

    /**
     * 创建一个 10MB 的文件。
     *
     * @param filePath 文件路径
     * @throws IOException 如果文件创建失败
     */
    private static void create10MBFile(String filePath) throws IOException {
        int fileSize = 10* 1024* 1024 ; // 10MB
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
