import java.io.Serializable;
import java.math.BigInteger;

class Signature implements Serializable {

    private byte[] h;
    private BigInteger z;

    Signature(byte[] h, BigInteger z) {
        this.h = h;
        this.z = z;
    }

    byte[] getH() {return this.h;}
    BigInteger getZ() {return this.z;}
}