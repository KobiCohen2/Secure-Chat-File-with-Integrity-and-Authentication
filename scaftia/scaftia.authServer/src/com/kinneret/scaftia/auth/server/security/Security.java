package com.kinneret.scaftia.auth.server.security;

import com.kinneret.scaftia.auth.server.utils.ByteManipulation;
import javafx.util.Pair;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static com.kinneret.scaftia.auth.server.ui.Controller.conf;
import static com.kinneret.scaftia.auth.server.utils.CommonChars.SEPARATOR;
import static com.kinneret.scaftia.auth.server.utils.CommonChars.space;


/**
 * A class which contains encrypt/decrypt API's of files and strings
 */
public class Security {

    private static Cipher cipher;
    private static MessageDigest digest;
    private static Charset utf8 = Charset.forName("UTF8");
    private static Mac hMacSHA256;
    public static final int IV_NONCE_SIZE = 16;
    public static final int SESSION_KEY_SIZE = 32;

    static {
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            digest = MessageDigest.getInstance("SHA-256");
            hMacSHA256 = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to generate key, which encoded by utf-8 and hashed by SHA-256 algorithm
     * @return 256 bits key
     */
    public static byte[] generateKey(String key) {
        ByteBuffer buffer = utf8.encode(key);
        byte[] keyBytes = new byte[buffer.remaining()];
        buffer.get(keyBytes);
        return digest.digest(keyBytes);
    }

    /**
     * A method to generate random byes
     * @return byte array of random bytes
     */
    public static byte[] generateRandomBytes(int size) {
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] arr = new byte[size];
        randomSecureRandom.nextBytes(arr);
        return arr;
    }


    /**
     * A method to calculate HMAC-SHA256 digest
     * @param ivBytes - byte array of the iv
     * @param dataBytes - byte array of the data
     * @return digest of the given iv and data
     */
    private static String calcHmacSha256Digest(byte[] ivBytes, byte[] dataBytes)
    {
        byte[] macKey = generateKey(conf.getMacPassword());
        final SecretKeySpec secretKey = new SecretKeySpec(macKey, "HmacSHA256");
        try {
            hMacSHA256.init(secretKey);
            byte[] digest = hMacSHA256.doFinal(concByteArrays(ivBytes, dataBytes));
            return ByteManipulation.bytesToHex(digest);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * A method to check if hamc is valid
     * @param data - the data to check
     * @param receivedDigest - the received digest
     * @return true if the hmac is valid, false otherwise
     */
    public static boolean checkDigest(String data, String receivedDigest)
    {
        String digest = calcHmacSha256Digest(null, convertByteBufferToByteArray(utf8.encode(data)));
        return digest.equals(receivedDigest);
    }

    /**
     * A method to generate response
     * @param sender - the requestor
     * @param recipient - the recipient
     * @param nonce - the nonce
     * @param requestorKey - requestor auth key
     * @param recipientKey - recipient auth key
     * @return encrypted response
     */
    public static String generateMessage(String sender, String recipient, String nonce, String requestorKey, String recipientKey)
    {
        Pair<String, String> sessionKeyAndToken = generateToken(sender, recipientKey);
        String message = sessionKeyAndToken.getKey() + space + nonce + space + recipient + space + sessionKeyAndToken.getValue();
        return encryptMessage(message, requestorKey);
    }

    /**
     * A method to generate a token for the recipient
     * @param sender - the requestor
     * @param key - the recipient auth key
     * @return encrypted token
     */
    private static Pair<String, String> generateToken(String sender, String key)
    {
        byte[] sessionKeyBytes = generateRandomBytes(SESSION_KEY_SIZE);
        String sessionKey = ByteManipulation.bytesToHex(sessionKeyBytes);
        String token = sessionKey + space + sender;
        String encryptedToken = encryptMessage(token, key);
        return new Pair<>(sessionKey, encryptedToken);
    }


    /**
     * A method to encrypt a message
     * @param message - message to decrypt
     * @param key - key to encrypt with
     * @return encrypted message
     */
    public static String encryptMessage(String message, String key) {
        try {
            byte[] keyBytes = generateKey(key);
            byte[] ivBytes = generateRandomBytes(IV_NONCE_SIZE);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] encrypted = cipher.doFinal(convertByteBufferToByteArray(utf8.encode(message)));
            String hmacDigest = calcHmacSha256Digest(ivBytes, encrypted);
            return ByteManipulation.bytesToHex(encrypted) + SEPARATOR + ByteManipulation.bytesToHex(ivBytes) + SEPARATOR + hmacDigest;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * A method to convert byte buffer to byte array
     * @param buf - the given byte buffer
     * @return the byte array
     */
    private static byte[] convertByteBufferToByteArray(ByteBuffer buf)
    {
        byte[] arr = new byte[buf.remaining()];
        buf.get(arr);
        return arr;
    }

    /**
     * A method to concatenate two byte arrays
     * @param a - first byte array
     * @param b - second byte array
     * @return concatenated byte array
     */
    private static byte[] concByteArrays(byte[] a, byte[] b)
    {
        if (a == null)
            return b;
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
