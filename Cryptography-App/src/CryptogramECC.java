import java.io.Serializable;
import java.util.Arrays;

class CryptogramECC implements Serializable {

    private EllipticCurvePoint Z;
    private byte[] c;
    private byte[] t;
    private static final long serialVersionUID = 6529685098267757690L;


    CryptogramECC(EllipticCurvePoint Z, byte[] c, byte[] t) {
        this.Z = Z;
        this.c = c;
        this.t = t;
    }

    EllipticCurvePoint getZ() {return this.Z;}
    byte[] getC() {return this.c;}
    byte[] getT() {return this.t;}

    @Override
    public String toString() {
        return "Z= " + Z.getX() + " C= " + Arrays.toString(c) + "T= " + Arrays.toString(t);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
