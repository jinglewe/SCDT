package Mine;

import it.unisa.dia.gas.jpbc.Element;

public class ServerSet {
    public static Element CSsk;
    public static Element CSpk;
    public static Element CSsecret;
    public static String bsk_AS;
    public static String Add_AS;
    public static Element ASsecret;
    public static void SetCSK(){
        Element[] Ks = UserSet.generateK();
        CSsk = Ks[0];
        CSpk = Ks[1];
        CSsecret = UserSet.pairing.getZr().newRandomElement().getImmutable();
    }
    public static void SetAS(){
        bsk_AS = "cb9505e39aaf290d7a8ae4fb72c7583d84aae8f256877ff0bfe6bc525aaee5f0";
        Add_AS = "0x522b74B76a339A271b8b8E3D11f7d87100796b60";
        ASsecret = UserSet.pairing.getZr().newRandomElement().getImmutable();
    }
}
