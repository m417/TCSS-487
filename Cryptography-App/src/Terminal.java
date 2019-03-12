class Terminal {
    static void promptIntroduction() {
        System.out.println(">>>>");
        System.out.println("Welcome to our app!\n");
    }

    static void promptOptions() {
        System.out.println("Here are your options:");
        showAvailableOptions();
    }

    private static void showAvailableOptions() {
        System.out.println("\t1) Find a cryptographic hash of any given file or input text");
        System.out.println("\t2) Encrypt or Decrypt a given file symmetrically under a given passphrase");
        System.out.println("\t3) Generate an elliptic key pair file from a given passphrase");
        System.out.println("\t4) Encrypt / Decrypt a data file under a given elliptic public key file.");
        System.out.println("\t5) Sign / Verify a given data file");
        System.out.println("\t6) Exit");
        promptChoice();
    }

    static void encryptDecryptSymmetricallyOptions() {
        System.out.println("\t1) Encrypt a given data file symmetrically under a given passphrase");
        System.out.println("\t2) Decrypt a given symmetric cryptogram under a given passphrase");
        System.out.println("\t3) Back");
        promptChoice();
    }

    static void promptPassPhrase() {
        System.out.print("\n\tPlease enter a password / passphrase: ");
    }

    static void promptChoice() {
        System.out.print("\nPlease enter a valid option (invalid option numbers are ignored): ");
    }

    static void promptGoodbye() {
        System.out.println("\nTerminating program....");
        System.out.println(">>>>");
    }

    static void cryptographicHashOptions() {
        System.out.println("\t1) Find a cryptographic hash of a file");
        System.out.println("\t2) Find a cryptographic hash of any input text");
        System.out.println("\t3) Back");
        promptChoice();
    }

    static void promptInputText() {
        System.out.print("Please enter the string you want to hash: ");
    }

    static void publicKeyEncryptDecryptOptions() {
        System.out.println("\t1) Encrypt a data file with a public key file");
        System.out.println("\t2) Decrypt a file .CryptogramECC file with a password");
        System.out.println("\t3) Back");
        promptChoice();

    }

    static void signatureOptions() {
        System.out.println("\t1) Sign a given file from a given password and write the signature to a file");
        System.out.println("\t2) Verify a given data file and its signature file under a given public key file");
        System.out.println("\t3) Back");
        promptChoice();

    }
}
