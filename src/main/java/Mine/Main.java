package Mine;

import Mine.entity.BlockData;
import Mine.entity.user;
import Mine.util.CryptoUtil;
import Mine.util.StringUtil;
import it.unisa.dia.gas.jpbc.Element;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;

public class Main {
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    public static byte[] concatArrays(byte[]... arrays){
        // 计算总长度
        int totalLength = 0;
        for (byte[] array : arrays) {
            if (array != null) {  // 处理可能的null数组
                totalLength += array.length;
            }
        }

        // 创建结果数组
        byte[] result = new byte[totalLength];

        // 复制数据
        int currentPos = 0;
        for (byte[] array : arrays) {
            if (array != null && array.length > 0) {
                System.arraycopy(array, 0, result, currentPos, array.length);
                currentPos += array.length;
            }
        }
        return result;
    }
    public static void main(String[] args) throws Exception {
        ServerSet.SetAS();
        ServerSet.SetCSK();  //初始化
        user alice = new user(); //sender
        UserSet.Init(alice);
        String pw = "shianShisd153#$%"; //需用户保存的口令

        Long blindBegin = System.nanoTime();
        Element r = UserSet.pairing.getZr().newRandomElement().getImmutable();
        Element BlindM = PassHarden.blindM(pw,r); //盲化
        System.out.println("pw*：" + BlindM.toBytes().length);
        Long blindEnd = System.nanoTime();
        System.out.println("Blind Time:" + (blindEnd-blindBegin)*Math.pow(10,-6) + "ms");

        Long SigBegin = System.nanoTime();
        Element sigStar = PassHarden.Sign(BlindM,ServerSet.CSsk); //CS Sign
        Long SigEnd = System.nanoTime();
        System.out.println("Sig Time:" + (SigEnd-SigBegin)*Math.pow(10,-6) + "ms");

        Long hashBegin = System.nanoTime();
        byte[] hpw = PassHarden.Vrfy(sigStar,ServerSet.CSpk,pw,r); //计算hpw
        Long hashEnd = System.nanoTime();
        System.out.println("hash Time:" + (hashEnd-hashBegin)*Math.pow(10,-6) + "ms");
        Long PassHardenTime = (hashEnd-hashBegin)+(blindEnd-blindBegin);
        System.out.println("PassHard Time:" + PassHardenTime*Math.pow(10,-6) + "ms"); //用户Passharden总时间
        alice.s = UserSet.pairing.getZr().newRandomElement().getImmutable();
        alice.r = UserSet.pairing.getZr().newRandomElement().getImmutable();

        //AS计算密文并存储
        Long AS_c1_begin = System.nanoTime();
        Element hpwElem = UserSet.pairing.getG2().newElement();
        hpwElem.setFromBytes(hpw);
        Element k1 = hpwElem.mulZn(ServerSet.ASsecret);
        byte[] c1 = CryptoUtil.AESEncrypt(k1.toBytes(),concatArrays(hpw,alice.s.toBytes(),alice.r.toBytes()));
        Long AS_c1_end = System.nanoTime();
        System.out.println("AS_c1 Time:" + (AS_c1_end-AS_c1_begin)*Math.pow(10,-6) + "ms");
        //AS计算明文并返回
        Long AS_m1_begin = System.nanoTime();
        Element k1_dec = hpwElem.mulZn(ServerSet.ASsecret);
        byte[] m1 = CryptoUtil.AESDecrypt(k1_dec.toBytes(),c1);
        Long AS_m1_end = System.nanoTime();
        System.out.println("AS_m1 Time:" + (AS_m1_end-AS_m1_begin)*Math.pow(10,-6) + "ms");

        Long tBegin = System.nanoTime();
        byte[] t = PassHarden.ComT(alice.s,pw);
        Long tEnd = System.nanoTime();
        System.out.println("t time:" + (tEnd-tBegin)*Math.pow(10,-6) + "ms"); //应该包含hpw获取时间+t计算时间+ct加密时间

        Long restoreBegin = System.nanoTime();
        byte[] ct = PassHarden.Restore(alice.s,alice.r, pw);
        Long restoreEnd = System.nanoTime();
        System.out.println("Restore time:" + ((restoreEnd-restoreBegin)+PassHardenTime)*Math.pow(10,-6) + "ms"); //应该包含hpw获取时间+t计算时间+ct加密时间

        //CS计算密文并存储
        Long CS_c2_begin = System.nanoTime();
        Element tElem = UserSet.pairing.getG2().newElement();
        tElem.setFromBytes(t);
        Element k2 = tElem.mulZn(ServerSet.CSsecret);
        byte[] c2 = CryptoUtil.AESEncrypt(k2.toBytes(),concatArrays(t,ct));
        Long CS_c2_end = System.nanoTime();
        System.out.println("CS_c2 Time:" + (CS_c2_end-CS_c2_begin)*Math.pow(10,-6) + "ms");
        //CS计算明文并返回
        Long CS_m2_begin = System.nanoTime();
        Element k2_dec = tElem.mulZn(ServerSet.CSsecret);
        byte[] m2 = CryptoUtil.AESDecrypt(k2_dec.toBytes(),c2);
        Long CS_m2_end = System.nanoTime();
        System.out.println("CS_m2 Time:" + (CS_m2_end-CS_m2_begin)*Math.pow(10,-6) + "ms");

        Long retriBegin = System.nanoTime();
        Element k_re = PassHarden.Retri(alice.s,alice.r,pw,ct);
        Long retriEnd = System.nanoTime();
        System.out.println("Retri time:" + ((retriEnd-retriBegin)+PassHardenTime)*Math.pow(10,-6) + "ms"); //应该包含hpw获取时间+t计算时间+ct解密时间

        BlockData bd = new BlockData();
        Long authBegin = System.nanoTime();
        Element AuthSig = Auth.AuthID(alice,k_re,bd);
        Long authEnd = System.nanoTime();
        System.out.println("U_Ipk time:" + (authEnd-authBegin)*Math.pow(10,-6) + "ms");
        try (FileWriter writer = new FileWriter("src/main/java/Mine/output/data.txt")) {
            writer.write(StringUtil.bytesToHex(StringUtil.BlockDataToByte(bd)));
        } catch (IOException e) {
            e.printStackTrace();
        }

        Long ASauthBegin = System.nanoTime();
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] dst = digest.digest(alice.ID.getBytes());
        Element auth = UserSet.pairing.getG2().newElement();
        auth.setFromBytes((alice.ID+alice.Add_U).getBytes());
        Element left = UserSet.pairing.pairing(AuthSig,UserSet.P_2);
        Element right = UserSet.pairing.pairing(auth,alice.ipk);
        if(left.isEqual(right)){
            System.out.println("Auth succ");
        }
        else {System.out.println("Auth fail");}
        Long ASauthEnd = System.nanoTime();
        System.out.println("U_Ipk time:" + (ASauthEnd-ASauthBegin)*Math.pow(10,-6) + "ms");

        Long updateBegin = System.nanoTime();
        Element SigSpk = Auth.UpdateK(alice,k_re);
        Long updateEnd = System.nanoTime();
        System.out.println("U_Update time:" + (updateEnd-updateBegin)*Math.pow(10,-6) + "ms");

        Long ASupBegin = System.nanoTime();
        Element left2 = UserSet.pairing.pairing(SigSpk,UserSet.P_2);
        Element right2 = UserSet.pairing.pairing(alice.spk,alice.ipk);
        if(left2.isEqual(right2)){
            System.out.println("Update succ");
        }
        else {System.out.println("Update fail");}
        Long ASupEnd = System.nanoTime();
        System.out.println("U_Spk time:" + (ASupEnd-ASupBegin)*Math.pow(10,-6) + "ms");

//        BigInteger cre = PassHarden.credit(hpw,alice.ID);
//        byte[] cEpsilon = PassHarden.EncEpsilon(cre.toByteArray(),epsilon);
//        System.out.println("cre:" + cre.toByteArray().length);
//        System.out.println("ce:" + cEpsilon.length);
//        Long ComputeEnd = System.nanoTime();
//        System.out.println("User Compute Time:" + (ComputeEnd-ComputeBegin) + "ns");
//        Long VrfyBegin = System.nanoTime();
//        boolean isEqu = PassHarden.Record(cEpsilon,epsilon,cre.toByteArray());
//        Long VrfyEnd = System.nanoTime();
//        System.out.println("Vrfy Time:" + (VrfyEnd-VrfyBegin) + "ns");
//        System.out.println(isEqu);
//        System.out.println(alice.Add_U.getBytes().length);
//        System.out.println(alice.ID.length());
//        byte[] cisk = CryptoUtil.AESEncrypt(hpw,alice.isk.toBytes());
//        System.out.println(cisk.length);
//        System.out.println(alice.ipk.toBytes().length);
//        System.out.println(alice.sig.toBytes().length);
//        System.out.println("block size:" + 160*3);
        int l_req = alice.ID.length()+ 4;
        int l_reg_as = (alice.ID.length())+ c1.length+4;
        int l_reg_cs = (alice.ID.length())+ c2.length+4;
        int l_L_as = alice.ID.length() + 2*alice.Add_U.length() + alice.cisk.length+alice.spk.getLengthInBytes()+SigSpk.getLengthInBytes();
        System.out.println("CS:"+(l_req+l_reg_cs));
        System.out.println("AS:"+(l_reg_as+l_L_as));
    }
}