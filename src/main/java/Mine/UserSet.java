package Mine;

import Mine.entity.*;
import Mine.util.CryptoUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.NoSuchAlgorithmException;

//产生用户的私有密钥信息
public class UserSet {
    //F-Curve
    public static Pairing pairing = PairingFactory.getPairing("a.properties");
    public static Element P_1 = pairing.getG1().newRandomElement().getImmutable();
    public static Element P_2 = pairing.getG2().newRandomElement().getImmutable();

    //密钥生成算法
    public static Element[] generateK(){
        Element sk = pairing.getZr().newRandomElement().getImmutable();
        Element pk = P_2.mulZn(sk).getImmutable();
        return new Element[]{sk,pk};
    }
    public static void IdentityKSet(user U){
        Element[] Ks = generateK();
        U.isk = Ks[0];
        U.ipk = Ks[1];
    }
    public static void SignKSet(user U){
        Element[] Ks = generateK();
        U.ssk = Ks[0];
        U.spk = Ks[1];
    }
    public static Element GetSig(Element sk, byte[] message) throws NoSuchAlgorithmException {
        Element hashM = CryptoUtil.stringHashToG(message.toString(), pairing.getG1(), pairing).getImmutable();
        return hashM.mulZn(sk).duplicate().getImmutable();
    }

    public static void Init(user U) throws NoSuchAlgorithmException{
        IdentityKSet(U);
        SignKSet(U);
        U.sig = GetSig(U.isk,U.spk.toBytes());
    }
    public static void ChainInit(user A){
        if (A.c.isSend) {
            CryptoUtil.dhRatchet(A.c);
            A.c.sendk = null;
            A.c.recvkey = null;
        }
        else {
            A.c.DHSendSk = A.ssk;
            A.c.DHSendPk = A.spk;
            A.c.DHRecvPk = null;
            A.c.sendk = null;
            A.c.recvkey = null;
        }
    }
}
