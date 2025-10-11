package Mine;

import Mine.util.CryptoUtil;
import it.unisa.dia.gas.jpbc.Element;


import java.security.MessageDigest;
import java.util.Arrays;

import static Mine.UserSet.pairing;

public class metaTest {
    public static void main(String[] args) throws Exception {
        Element P_1 = pairing.getG1().newRandomElement().getImmutable();
        Element P_2 = pairing.getG2().newRandomElement().getImmutable();
        Element G_T = pairing.getGT().newRandomElement().getImmutable();
        Element rand = pairing.getZr().newRandomElement().getImmutable();
        byte[] key = "123456".getBytes();
        byte[] m = "abcd".getBytes();
        byte[] c = CryptoUtil.AESEncrypt(key,m);
        byte[] m1 = CryptoUtil.AESDecrypt(key,c);
        System.out.println(Arrays.toString(m1));

        Long Begin = System.nanoTime();

//        Element result = pairing.pairing(P_1,P_2);
//        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
//        byte[] hpw = digest.digest(("1234567890").getBytes());
        Long End = System.nanoTime();
//        System.out.println("Time:" + (End-Begin)*Math.pow(10,-6) + "ms");
    }

}
