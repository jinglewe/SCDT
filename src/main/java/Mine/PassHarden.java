package Mine;

import Mine.util.HKDF;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import Mine.util.CryptoUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Arrays;

public class PassHarden {
    //U盲化
    public static Element blindM(String m, Element r) throws NoSuchAlgorithmException {
        Long DecStartTime = System.nanoTime();
        Element hashM = CryptoUtil.stringHashToG(m, UserSet.pairing.getG1(), UserSet.pairing).getImmutable();
        return hashM.mulZn(r).duplicate().duplicate();
    }
    //CS签名
    public static Element Sign(Element mStar, Element sk){
        return mStar.mulZn(sk).duplicate().getImmutable();
    }
    //U去盲化并验签，输出hpw
    public static byte[] Vrfy(Element sigStar, Element pk, String pw, Element r) throws NoSuchAlgorithmException{
        Element sig = sigStar.mulZn(r.invert()).getImmutable();
        Element hashM = CryptoUtil.stringHashToG(pw, UserSet.pairing.getG1(), UserSet.pairing).getImmutable();
        Element left = UserSet.pairing.pairing(sig,UserSet.P_2);
        Element right = UserSet.pairing.pairing(hashM,pk);
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        if(left.isEqual(right)){
            return digest.digest((pw + sig.toString()).getBytes());
        }
        return null;
    }
    //U计算hpw
    public static byte[] hpw(Element sig, String pw) throws NoSuchAlgorithmException{

        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hpw = digest.digest((sig.toString() + pw).getBytes());

        return hpw;
    }
    //U计算credit
    public static BigInteger credit(byte[] hpw, String ID) throws NoSuchAlgorithmException{
        return CryptoUtil.hashToZp((Arrays.toString(hpw) + ID) , UserSet.pairing.getG1().getOrder());
    }
    //U计算加密后的随机验证值
    public static byte[] EncEpsilon(byte[] credit, Element epsilon) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        return CryptoUtil.AESEncrypt(credit,epsilon.toBytes());
    }
    //CS验证随机值密文的正确性，并更新用户记录
    public static boolean Record(byte[] cEpsilon, Element epsilon, byte[] credit) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        byte[] epsilonStarBytes = CryptoUtil.AESDecrypt(credit,cEpsilon);
        Element epsilonStar = UserSet.pairing.getZr().newElementFromBytes(epsilonStarBytes).getImmutable();
        return epsilonStar.equals(epsilon);
    }

    public static byte[] ComT(Element s, String pw){
        HKDF hkdf = new HKDF(s.toBytes(), pw.getBytes()); // 盐值可以为空
        return hkdf.expand("ComT".getBytes(), hkdf.keyLength);
    }
    public static byte[] Restore(Element s,Element r,String pw) throws Exception{
        Element k_re = UserSet.pairing.getZr().newRandomElement().getImmutable();
        System.out.println("restore"+ Arrays.toString(k_re.toBytes()));
        byte[] t = ComT(s,pw);
        HKDF hkdf2 = new HKDF(r.toBytes(), pw.getBytes());
        byte[] k = hkdf2.expand("ComK".getBytes(), hkdf2.keyLength);
        return CryptoUtil.AESEncrypt(k,k_re.toBytes());
    }
    public static Element Retri(Element s,Element r,String pw, byte[] ct)throws Exception{
        byte[] t = ComT(s,pw);
        HKDF hkdf2 = new HKDF(r.toBytes(), pw.getBytes());
        byte[] k = hkdf2.expand("ComK".getBytes(), hkdf2.keyLength);
        byte[] k_re_byte = CryptoUtil.AESDecrypt(k,ct);

        Element k_re = UserSet.pairing.getZr().newElement();
        k_re.setFromBytes(k_re_byte);
        System.out.println("retri"+ Arrays.toString(k_re.toBytes()));
        return k_re;
    }

}
