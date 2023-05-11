import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Main {
    public static void main(String[] args) throws Exception {
        // Message
        String message = "This is PKI Test, Hello PKI!";

        // Generate keypair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();


        // Encrypt the message by the public key
        byte[] encryptedMessage = encryptMessage(message, publicKey);
        System.out.println(encryptedMessage);

        // Decrypt the message by the private key
        String decryptedMessage = decryptMessage(encryptedMessage, privateKey);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // Generate a new RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        System.out.println(keyPairGenerator.genKeyPair().getPublic());
        System.out.println(keyPairGenerator.genKeyPair().getPrivate());
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {
        // Create a cipher with the RSA algorithm
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt the message
        return cipher.doFinal(message.getBytes());
    }

    public static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        // Create a cipher with the RSA algorithm
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Decrypt the message
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }
}
