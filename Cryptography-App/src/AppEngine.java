import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

class AppEngine {
    private Scanner consoleScanner;

    AppEngine() {
        this.consoleScanner = new Scanner(System.in);
        Terminal.promptIntroduction();
    }

    void startSequence() {
        Terminal.promptOptions();
        this.onOptionEntered(this.consoleScanner.next());
    }

    private void onOptionEntered(String option) {
        switch (option) {
            case "1": // cryptographic hash
                Terminal.cryptographicHashOptions();
                this.hashOptions();
            case "2": // encrypt/decrypt KMAC
                Terminal.encryptDecryptSymmetricallyOptions();
                this.encryptDecryptSymetricOptions();;
            case "3": //Generate an elliptic key pair file
                this.generateKeyPair();
                this.startSequence();
            case "4": // Encrypt / Decrypt  a data file under a given elliptic public key file.
                Terminal.publicKeyEncryptDecryptOptions();
                this.encryptDecryptECCOptions();
            case "5": // exit
                Terminal.signatureOptions();
                this.signatureOptions();
            case "6": // exit
                Terminal.promptGoodbye();
                System.exit(1);
            default: // invalid input
                Terminal.promptChoice();
                this.onOptionEntered(this.consoleScanner.next());
        }
    }

    private void signatureOptions() {
        String subOption = this.consoleScanner.next();
        switch (subOption) {
            case "1": //sign a file
                this.signFile();
                this.startSequence();
            case "2": // verify a file
                this.verifyFileSignature();
                this.startSequence();
            case "3":  // back
                this.startSequence();
            default: // invalid input
                Terminal.promptChoice();
                hashOptions();
        }
    }

    private void signFile() {
        Terminal.promptPassPhrase();
        this.consoleScanner = new Scanner(System.in);
        String passphrase = this.consoleScanner.nextLine();
        System.out.println("\nPlease select a data file\n");

        JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
        int result = fileChooser.showOpenDialog(null);

        if (result == JFileChooser.CANCEL_OPTION) {
            System.out.println("You did not select any file");
        } else {
            SignatureManager.generateSignature(passphrase, fileChooser);
        }
    }

    private void verifyFileSignature() {

        System.out.println("\nPlease select a public key file you generated from part 3\n");
        JFileChooser public_key_fc = new JFileChooser(System.getProperty("user.dir"));
        JFileChooser file_fc = new JFileChooser(System.getProperty("user.dir"));
        JFileChooser sig_fc = new JFileChooser(System.getProperty("user.dir"));

        int result = public_key_fc.showOpenDialog(null);
        if (result == JFileChooser.CANCEL_OPTION) {
            System.out.println("You did not select a public key file");
        } else {

            System.out.println("\nPlease select a data file\n");

            result = file_fc.showOpenDialog(null);
            if (result == JFileChooser.CANCEL_OPTION) {
                System.out.println("You did not select a data file");
            } else {

                System.out.println("\nPlease select a Signature file\n");

                result = sig_fc.showOpenDialog(null);
                if (result == JFileChooser.CANCEL_OPTION) {

                    System.out.println("You did not select a signature file");

                } else {

                    SignatureManager.verifySignature(public_key_fc, file_fc, sig_fc);

                }
            }
        }
    }

    private void encryptDecryptECCOptions() {
        String subOption = this.consoleScanner.next();
        switch (subOption) {
            case "1": //encrypt
                this.encryptECC();
                this.startSequence();
            case "2": // decrypt
                this.decryptECC();
                this.startSequence();
            case "3":  // back
                this.startSequence();
            default: // invalid input
                Terminal.promptChoice();
                hashOptions();
        }
    }

    private void encryptECC() {

        System.out.println("\nPlease select a public key file you generated from part 3\n");
        JFileChooser public_key_fc = new JFileChooser(System.getProperty("user.dir"));
        JFileChooser file_fc = new JFileChooser(System.getProperty("user.dir"));

        int result = public_key_fc.showOpenDialog(null);
        if (result == JFileChooser.CANCEL_OPTION) {
            System.out.println("You did not select a public key file");
        } else {

            System.out.println("\nPlease select a file to encrypt\n");

            result = file_fc.showOpenDialog(null);
            if (result == JFileChooser.CANCEL_OPTION) {
                System.out.println("You did not select a file to encrypt");
            } else {
                EllipticCurveCryptography.encryptFile(public_key_fc, file_fc);

            }
        }
    }

    private void decryptECC() {
        Terminal.promptPassPhrase();
        this.consoleScanner = new Scanner(System.in);
        String passphrase = this.consoleScanner.nextLine();
        System.out.println("Please select a .CryptogramECC file to decrypt\n");
        JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
        int result = fileChooser.showOpenDialog(null);
        if (result == JFileChooser.CANCEL_OPTION) {
            System.out.println("You did not select any file");
        } else {
            if (fileChooser.getSelectedFile().toString().endsWith(".CryptogramECC")) {
                EllipticCurveCryptography.decrypt(passphrase, fileChooser);
            } else {
                System.out.println("You did not select the correct file type.");
            }
        }


    }

    private void generateKeyPair() {
        Terminal.promptPassPhrase();
        this.consoleScanner = new Scanner(System.in);
        String passphrase = this.consoleScanner.nextLine();
        EllipticCurveCryptography.generateKeyPair(passphrase);
    }

    private void encryptDecryptSymetricOptions() {
        String subOption = this.consoleScanner.next();
        switch (subOption) {
            case "1": //encrypt
                try {
                    this.encryptFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                this.startSequence();
            case "2": // decrypt
                try {
                    this.decryptFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                this.startSequence();
            case "3":  // back
                this.startSequence();
            default: // invalid input
                Terminal.promptChoice();
                hashOptions();
        }
    }

    private void encryptFile() throws IOException {
        Terminal.promptPassPhrase();
        this.consoleScanner = new Scanner(System.in);
        String passphrase = this.consoleScanner.nextLine();
        FileDialog fd = new FileDialog(new JFrame(), "Choose a file to encrypt", FileDialog.LOAD);
        fd.setVisible(true);
        if (fd.getFile() == null) {
            System.out.println("\nYou did not select a file.\n\n");
        } else {
            KMACXOF256.encryptFile(fd, passphrase);
        }
    }

    private void decryptFile() throws IOException {
        Terminal.promptPassPhrase();
        this.consoleScanner = new Scanner(System.in);
        String passphrase = this.consoleScanner.nextLine();
        FileDialog fd = new FileDialog(new JFrame(), "Choose a .cryptogram file to decrypt", FileDialog.LOAD);
        fd.setVisible(true);
        String fileName = fd.getFile();
        if (fileName == null) {
            System.out.println("\nYou did not select a file.\n\n");
        } else if (!fileName.endsWith(".cryptogram")) {
            System.out.println("\nYou did not select a .cryptogram file.\n\n");
        } else {
            KMACXOF256.decryptFile(fd, passphrase);
        }
    }


    private void hashOptions() {
        String subOption = this.consoleScanner.next();
        switch (subOption) {
            case "1": // file
                try {
                    hashFileInput();
                } catch (IOException e) { e.printStackTrace(); }
                this.startSequence();
            case "2": // input text
                hashInputText();
                this.startSequence();
            case "3":  // back
                this.startSequence();
            default: // invalid input
                Terminal.promptChoice();
                hashOptions();
        }
    }

    private void hashInputText() {
        Terminal.promptInputText();
        this.consoleScanner = new Scanner(System.in); // instantiate new scanner to flush out \n characters
        String textToHash = this.consoleScanner.nextLine();

        String result = KMACXOF256.getCryptographicHash("".getBytes(), textToHash.getBytes(),
                512, /*"My Tagged Application".getBytes()*/ "D".getBytes());
        System.out.println("Done! Your text \"" + textToHash + "\" hashed to ->  " + result +  "\n\n");
    }

    private void hashFileInput() throws IOException {
        FileDialog fd = new FileDialog(new JFrame(), "Choose a file", FileDialog.LOAD);
        fd.setVisible(true);
        String filename = fd.getFile();
        if (filename == null) {
            System.out.println("\nYou did not select a file.\n\n");
        } else {
            Path path = Paths.get(fd.getDirectory() + fd.getFile());
            byte[] data = Files.readAllBytes(path);
            String result = KMACXOF256.getCryptographicHash("".getBytes(), (new String(data)).getBytes(),
                    512, "D".getBytes());
            System.out.println("Done! Your file \"" + fd.getFile() + "\" hashed to ->  " + result +  "\n\n");
        }
    }
}
