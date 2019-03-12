import java.io.Serializable;
import java.math.BigInteger;

class EllipticCurvePoint implements Serializable {

    private BigInteger x;
    private BigInteger y;
    private static final long serialVersionUID = 6529685098267757690L;

    EllipticCurvePoint(BigInteger x, BigInteger y) {
        this.x = x.mod(EllipticCurveCryptography.MERSENNE_PRIME);
        this.y = y.mod(EllipticCurveCryptography.MERSENNE_PRIME);
    }

    BigInteger getX() {
        return this.x;
    }

    BigInteger getY() {
        return this.y;
    }

    // neutral point constructor
    EllipticCurvePoint() {
        this(BigInteger.ZERO, BigInteger.ONE);

    }

    EllipticCurvePoint(BigInteger x, boolean leastSignificantBit) {
        this.x = x;
        //𝑦 = ±√(1 − 𝑥2)/(1 + 376014𝑥2) mod 𝑝
        BigInteger x2 = x.modPow(new BigInteger("2"),  EllipticCurveCryptography.MERSENNE_PRIME);
        BigInteger part1 = BigInteger.ONE.subtract(x2);
        BigInteger part2 = BigInteger.ONE.add(BigInteger.valueOf(EllipticCurveCryptography.D * -1)
                .multiply(x2).mod( EllipticCurveCryptography.MERSENNE_PRIME));
        BigInteger y = sqrt(part1.multiply(part2.modInverse( EllipticCurveCryptography.MERSENNE_PRIME)),
                EllipticCurveCryptography.MERSENNE_PRIME, leastSignificantBit);
        this.y = y;
    }


    static EllipticCurvePoint getBasePoint() {
        return new EllipticCurvePoint(BigInteger.valueOf(18), false);
    }

    private BigInteger getRadicand(BigInteger x) {
        BigInteger numerator = BigInteger.ONE.subtract(x.pow(2)).mod(EllipticCurveCryptography.MERSENNE_PRIME);
        BigInteger denominator = BigInteger.ONE.add(x.pow(2)
                .multiply(BigInteger.valueOf(EllipticCurveCryptography.D * -1))
                .modInverse(EllipticCurveCryptography.MERSENNE_PRIME));
        return numerator.divide(denominator);
    }

    static EllipticCurvePoint selfMultiply (BigInteger s, EllipticCurvePoint base) {
        EllipticCurvePoint toSend = base;
        String x = s.toString(2);
        for (int i = x.length() - 1; i >= 0; i--) {
            toSend = toSend.summation(toSend);
            if (x.charAt(i) == '1') {
                toSend = toSend.summation(base);
            }
        }
        return toSend;
    }

    // The opposite of a point (𝑥,𝑦) is the point (−𝑥,𝑦),
    EllipticCurvePoint getOppositePoint() {
        return new EllipticCurvePoint(x.multiply(BigInteger.valueOf(-1)), y);
    }

    /** Taken from spec.
     * Compute a square root of v mod p with a specified
     * least significant bit, if such a root exists. *
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * *@return a squareroot r of v mod p with r mod 2=1ifflsb=true if such a root exists, otherwise null.
     */

    private static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }


    EllipticCurvePoint summation(EllipticCurvePoint other) {
        BigInteger xNumerator = x.multiply(other.y).add(y.multiply(other.x));
        BigInteger intermediate = BigInteger.valueOf(EllipticCurveCryptography.D)
                .multiply(x).multiply(y).multiply(other.x).multiply(other.y);
        BigInteger xDenominator = BigInteger.ONE.add(intermediate);
        BigInteger yNumerator = y.multiply(other.y).subtract(x.multiply(other.x));
        BigInteger yDenominator = BigInteger.ONE.subtract(intermediate);
        BigInteger newX = xNumerator.multiply(xDenominator.modInverse(EllipticCurveCryptography.MERSENNE_PRIME))
                .mod(EllipticCurveCryptography.MERSENNE_PRIME);
        BigInteger newY = yNumerator.multiply(yDenominator.modInverse(EllipticCurveCryptography.MERSENNE_PRIME))
                .mod(EllipticCurveCryptography.MERSENNE_PRIME);
        return new EllipticCurvePoint(newX, newY);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof EllipticCurvePoint) {
            EllipticCurvePoint other = (EllipticCurvePoint) obj;
            return x.equals(other.x) && y.equals(other.y);
        }
        return false;
    }
}