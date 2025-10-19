package Mine;

import Mine.entity.BlockData;
import Mine.entity.user;
import Mine.util.CryptoUtil;
import Mine.util.StringUtil;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;

public class BatchBlockTest {
    public static void main(String[] args) throws Exception {
        int testNum = 60;
        String ASID = "0000000000000000";
        String AddKey = "0x12e0d9794958a8b9aaea3c55bc2437c118822458d27cae5f1dd6a0ae4a67e702";

        user[] Users = new  user[testNum];
        for(int i=0; i<testNum; i++){
            BlockData bd = new BlockData();
            user U = new user();
            UserSet.Init(U);
//            U.r = UserSet.pairing.getZr().newRandomElement().getImmutable();
//            U.s = UserSet.pairing.getZr().newRandomElement().getImmutable();
//            U.k_re = UserSet.pairing.getZr().newRandomElement().getImmutable();
//            Users[i] = U; //sender
//            bd.cisk = CryptoUtil.AESEncrypt(U.k_re.toBytes(), U.isk.toBytes());
//            bd.cbsk = CryptoUtil.AESEncrypt(U.k_re.toBytes(), U.bsk_U.getBytes());
//            bd.ipk = U.ipk.toBytes();
//            String data = StringUtil.bytesToHex(StringUtil.BlockDataToByte(bd));
//            try (FileWriter writer = new FileWriter(String.format("src/main/java/Mine/output/data_%d.txt", i))) {
//                writer.write(data);
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
            byte[][] datas = new byte[][]{ASID.getBytes(),AddKey.getBytes(), U.ipk.toBytes()};
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            for (byte[] arr : datas) {
                outputStream.write(arr);
            }
            byte[] AuthData =outputStream.toByteArray();
            try (FileWriter writer = new FileWriter(String.format("src/main/java/Mine/output/dataAS_%d.txt", i))) {
                writer.write(StringUtil.bytesToHex(AuthData));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
