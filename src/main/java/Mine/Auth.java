package Mine;

import Mine.entity.user;
import Mine.util.CryptoUtil;
import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;

public class Auth {
    public static Element AuthID(user u, Element k_re) throws Exception{
        byte[] cbsk = CryptoUtil.AESEncrypt(k_re.toBytes(),u.bsk_U.getBytes());
        u.cisk = CryptoUtil.AESEncrypt(k_re.toBytes(),u.isk.toBytes());
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] dst = digest.digest(u.ID.getBytes());
        Element hashM = CryptoUtil.stringHashToG((u.ID+u.Add_U), UserSet.pairing.getG1(), UserSet.pairing).getImmutable();
        u.sig = hashM.mulZn(u.isk).duplicate().duplicate();
        Element Auth = UserSet.pairing.getG2().newElement();
        Auth.setFromBytes((u.ID+u.Add_U).getBytes());
        Element Sig = Auth.mulZn(u.isk).duplicate().duplicate();
        return Sig;
    }

    public static Element UpdateK(user u, Element k_re) throws Exception{
        byte[] isk_byte = CryptoUtil.AESDecrypt(k_re.toBytes(),u.cisk);
        byte[] cssk = CryptoUtil.AESEncrypt(k_re.toBytes(),u.ssk.toBytes());
        Element isk = UserSet.pairing.getZr().newElement();
        isk.setFromBytes(isk_byte);
        return u.spk.mulZn(isk);
    }
}
