package Mine.entity;

import Mine.util.CryptoUtil;
import it.unisa.dia.gas.jpbc.Element;

public class chains {
    public byte[] rk;
    public byte[] sendk;
    public byte[] recvkey;
    public Element DHSendSk;
    public Element DHSendPk;
    public Element DHRecvPk;
    public Element dhOut;
    public boolean isSend;
    public chains(byte[] rk, boolean isSend) {
        this.rk = rk;
        this.isSend = isSend;
        this.dhOut = null;
    }
}
