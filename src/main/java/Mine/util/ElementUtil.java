package Mine.util;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ElementUtil {
    public static Element mapIntToElement(int value, Field field) throws NoSuchAlgorithmException {
        // Convert the int value to bytes
        byte[] valueBytes = ByteBuffer.allocate(Integer.BYTES).putInt(value).array();

        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(valueBytes);

        // Map the hashed bytes to a field element
        Element mappedElement = field.newElementFromHash(hash, 0, hash.length).getImmutable();

        return mappedElement;
    }

    public static int getElementValue(Element element) {
        // Extract the integer value from the element
        BigInteger intValue = element.toBigInteger();

        // Convert the BigInteger value to an int
        return intValue.intValue();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing("f.properties");

        int i1 = 1;
        int i2 = 2;
        Element e1 = mapIntToElement(i1, pairing.getG1());
        Element e2 = mapIntToElement(i2, pairing.getG1());
        Element result = e1.add(e2).sub(e2);
        System.out.println();
    }
}
