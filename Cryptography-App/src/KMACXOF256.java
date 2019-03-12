import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

class KMACXOF256 {

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    private KMACXOF256() { }

    static String getCryptographicHash(byte[] key, byte[] message,
                                              int length, byte[] diversification) {
        return convertBytesToHex(SHAKE.KMACXOF256(key, message, length, diversification));
    }


    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder solution = new StringBuilder();
        for (byte aByte : bytes) {
            int v = aByte & 0xFF;
            solution.append(HEX_ARRAY[v >>> 4]); // print the left 4 digits first
            solution.append(HEX_ARRAY[v & 0x0F]); // print the right 4 digits first
        }
        return solution.toString();
    }

    static void encryptFile(FileDialog dialog, String passphrase) throws IOException {
        String fileLocation = dialog.getDirectory() + dialog.getFile();
        Path path = Paths.get(fileLocation);
        byte[] message = Files.readAllBytes(path);
        byte[] pw = (passphrase != null && passphrase.length() > 0) ? passphrase.getBytes() : new byte[0];
        try {
            FileOutputStream outputStream = new FileOutputStream(fileLocation + ".cryptogram");
            outputStream.write(getOutputContents(message, pw));
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Your file has been encrypted! Your file " + dialog.getFile() +
                " encrypted to " + convertBytesToHex(message));
    }

    private static byte[] concatenateByteArray(byte[] arr1, byte[] arr2) throws IOException {
        ByteArrayOutputStream toSend = new ByteArrayOutputStream();
        toSend.write(arr1);
        toSend.write(arr2);
        return toSend.toByteArray();
    }

    private static byte[] getOutputContents(byte[] message, byte[] pw) throws IOException {
        // z = Random(512)
        SecureRandom random = new SecureRandom();
        byte[] z = new byte[64]; //64 * 8 = 512
        random.nextBytes(z);

        //(ke || ka) = KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] ke_II_ka = SHAKE.KMACXOF256(concatenateByteArray(z, pw), "".getBytes(), 1024, "S".getBytes());

        //c = KMACXOF256(ke, “”, |m|, “SKE”) XOR m
        byte[] ke = Arrays.copyOfRange(ke_II_ka, 0, 64);
        byte[] intermediateResult = SHAKE.KMACXOF256(ke, "".getBytes(), 8 * message.length, "SKE".getBytes());
        byte[] c = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            c[i] = (byte) (intermediateResult[i] ^ message[i]);
        }

        // t = KMACXOF256(ka, m, 512, “SKA”)
        byte[] ka = Arrays.copyOfRange(ke_II_ka, 64, 128);
        byte[] t = SHAKE.KMACXOF256(ka, message, 512, "SKA".getBytes());

        //symmetric cryptogram: (z, c, t)
        ByteArrayOutputStream toSend = new ByteArrayOutputStream();
        toSend.write(z);
        toSend.write(c);
        toSend.write(t);
        return toSend.toByteArray();
    }

    static void decryptFile(FileDialog fd, String passphrase) throws IOException {
        String fileLocation = fd.getDirectory() + fd.getFile();
        Path path = Paths.get(fileLocation);
        byte[] cryptogram = Files.readAllBytes(path);
        byte[] pw = (passphrase != null && passphrase.length() > 0) ? passphrase.getBytes() : new byte[0];
        DecryptionResult result = getMessage(cryptogram, pw);
        if (result.tPrimeEqualsT) {
            System.out.println("Your .cryptogram file " + fd.getFile() + " decrypted to: " + convertBytesToHex(result.m));
        } else {
            System.out.println("t' does not equal t. Rejected. Passwords must match.");
        }
    }


    private static DecryptionResult getMessage(byte[] cryptogram, byte[] pw) throws IOException {
        // Get z
        byte[] z = Arrays.copyOfRange(cryptogram, 0, 64);

        // Get t
        byte[] t = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);

        // Get (ke || ka)
        byte[] ke_II_ka = SHAKE.KMACXOF256(concatenateByteArray(z, pw), "".getBytes(), 1024, "S".getBytes());

        // Get c
        byte[] c = Arrays.copyOfRange(cryptogram,64, cryptogram.length - 64);

        // Get m
        byte[] intermediate = SHAKE.KMACXOF256(Arrays.copyOfRange(ke_II_ka, 0, 64),
                "".getBytes(), c.length * 8, "SKE".getBytes());

        byte[] m = new byte[c.length];
        for (int i = 0; i < c.length; i++) {
            m[i] = (byte) (c[i] ^ intermediate[i]);
        }

        // Get t'
        byte[] tPrime = SHAKE.KMACXOF256(Arrays.copyOfRange(ke_II_ka, 64, 128), m, 512, "SKA".getBytes());
        return new DecryptionResult(m, Arrays.equals(t, tPrime));
    }


    private static class DecryptionResult {
        byte[] m;
        boolean tPrimeEqualsT;

        DecryptionResult(byte[] m, boolean tPrimeEqualsT) {
            this.m = m;
            this.tPrimeEqualsT = tPrimeEqualsT;
        }
    }
}
