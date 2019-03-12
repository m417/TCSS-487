import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

class EllipticCurveCryptography {

    static final BigInteger MERSENNE_PRIME = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
    static final Integer D = -376014;


    static void generateKeyPair(String password) {
        // s  = KMACXOF256(pw, “”, 512, “K”);
        byte[] intermediate = SHAKE.KMACXOF256(password.getBytes(), "".getBytes(), 512, "K".getBytes());
        // s  = 4s

        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(intermediate)); // private key
        // V = s*G
        EllipticCurvePoint v = EllipticCurvePoint.selfMultiply(s, EllipticCurvePoint.getBasePoint());

        System.out.println("\nPlease select destination directory for public key output.\n");
        final JFileChooser fc = new JFileChooser(System.getProperty("user.dir"));
        try {
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            EventQueue.invokeAndWait(() -> fc.showOpenDialog(null));
            FileOutputStream fos = new FileOutputStream(fc.getSelectedFile().toString()
                    + "/public_key_file_password=" + password);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(v);
            oos.close();
            System.out.println("Private Key: " + s.toString());
            System.out.println("Public Key X : " + v.getX().toString());
            System.out.println("Public Key Y : " + v.getY().toString());
            System.out.println("\nYour public key file has been saved to the destination: "
                    + fc.getSelectedFile().toString() + "/public_key_file_password=" + password + "\n");
        } catch (InterruptedException | IOException | InvocationTargetException e) {
            e.printStackTrace();
        } catch (NullPointerException e) { System.out.println("You did not select a directory.\n"); }

    }

    static void encryptFile(JFileChooser public_key_fc, JFileChooser file_fc) {
        String publicKeyFileLocation = public_key_fc.getSelectedFile().toString();
        String toEncryptFileLocation = file_fc.getSelectedFile().toString();
        byte[] encryptFileContents = new byte[0];
        FileInputStream inputStream;
        ObjectInputStream objectInputStream = null;
        try {
            encryptFileContents = Files.readAllBytes(Paths.get(toEncryptFileLocation));
            inputStream = new FileInputStream(publicKeyFileLocation);
            objectInputStream = new ObjectInputStream(inputStream);
        } catch (IOException e) { e.printStackTrace(); }
        //z = Random(512)
        SecureRandom random = new SecureRandom();
        byte[] z = new byte[64]; // 64 * 8 = 512
        random.nextBytes(z);



        //k = 4z
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(z));
        // W = k * V where V is the public key file
        EllipticCurvePoint V = null;
        try {
            V = (EllipticCurvePoint) objectInputStream.readObject();
        } catch (ClassNotFoundException | IOException e) { e.printStackTrace(); }
        EllipticCurvePoint W = EllipticCurvePoint.selfMultiply(k, V);


        // Z = k*G
        EllipticCurvePoint Z = EllipticCurvePoint.selfMultiply(k, EllipticCurvePoint.getBasePoint());
        //(ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
        byte[] ke_II_ka = SHAKE.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
        //c = KMACXOF256(ke, “”, |m|, “PKE”) XOR m

        byte[] ke = Arrays.copyOfRange(ke_II_ka, 0, 64);

        byte[] intermediateResult = SHAKE.KMACXOF256(ke, "".getBytes(), encryptFileContents.length * 8, "PKE".getBytes());
        byte[] c = new byte[encryptFileContents.length];
        for (int i = 0; i < encryptFileContents.length; i++) {
            c[i] = (byte) (encryptFileContents[i] ^ intermediateResult[i]);
        }
        // t =  KMACXOF256(ka, m, 512, “PKA”)
        byte[] ka = Arrays.copyOfRange(ke_II_ka, 64, 128);

        byte[] t = SHAKE.KMACXOF256(ka, encryptFileContents, 512, "PKA".getBytes());

        CryptogramECC result = new CryptogramECC(Z, c, t);
        FileOutputStream fos;
        try {
            fos = new FileOutputStream(file_fc.getSelectedFile() + ".CryptogramECC");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(result);
            oos.close();
        } catch (IOException e) { e.printStackTrace(); }
        System.out.println("File Encrypted: " + bytesToHex(encryptFileContents));

    }

    static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    static void decrypt(String password, JFileChooser fileChooser) {
        String fileLocation = fileChooser.getSelectedFile().toString();
        FileInputStream inputStream;
        ObjectInputStream objectInputStream;
        CryptogramECC recoveredCryptogram = null;
        try {
            inputStream = new FileInputStream(fileLocation);
            objectInputStream = new ObjectInputStream(inputStream);
            recoveredCryptogram = (CryptogramECC) objectInputStream.readObject();
        } catch (IOException | ClassNotFoundException e) { e.printStackTrace(); }

        EllipticCurvePoint Z = recoveredCryptogram.getZ();

        byte[] C = recoveredCryptogram.getC();
        byte[] T = recoveredCryptogram.getT();

        //s = KMACXOF256(pw, “”, 512, “K”);
        byte[] intermediate = SHAKE.KMACXOF256(password.getBytes(), "".getBytes(), 512, "K".getBytes());

        //s = 4s
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(intermediate));

        //W = s*Z
        EllipticCurvePoint W = EllipticCurvePoint.selfMultiply(s, Z);


        //(ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
        byte[] ke_II_ka = SHAKE.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());

        //m = KMACXOF256(ke, “”, |c|, “PKE”) XOR c
        byte[] ke = Arrays.copyOfRange(ke_II_ka, 0, 64);
        byte[] mPrime = SHAKE.KMACXOF256(ke, "".getBytes(), C.length * 8, "PKE".getBytes());
        byte[] m = new byte[C.length];
        for (int i = 0; i < m.length; i++) {
            m[i] = (byte) (mPrime[i] ^ C[i]);
        }

        //t’ = KMACXOF256(ka, m, 512, “PKA”)
        byte[] ka = Arrays.copyOfRange(ke_II_ka, 64, 128);

        byte[] tPrime = SHAKE.KMACXOF256(ka, m, 512, "PKA".getBytes());

        //accept if, and only if, t’ = t
        if (Arrays.equals(tPrime, T)) {
            System.out.println("File decrypted! Contents: " + (bytesToHex(m)));
        } else { System.out.println("TPrime did not equal T."); }
    }
}
