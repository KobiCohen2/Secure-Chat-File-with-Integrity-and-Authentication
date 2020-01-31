package com.kinneret.scaftia.security;

import com.kinneret.scaftia.utils.ByteManipulation;
import javafx.util.Pair;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static com.kinneret.scaftia.ui.Controller.conf;
import static com.kinneret.scaftia.utils.CommonChars.*;

/**
 * A class which contains encrypt/decrypt API's of files and strings
 */
public class Security {

    private static Cipher cipher;
    private static MessageDigest digest;
    private static Charset utf8 = Charset.forName("UTF8");
    private static Mac hMacSHA256;
    public static final int IV_NONCE_SIZE = 16;

    static {
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            digest = MessageDigest.getInstance("SHA-256");
            hMacSHA256 = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public enum SecurityToken{
        DECRYPTED_MESSAGE,
        IV,
        HMAC_DIGEST,
        HMAC_RESULT
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
     * A method to generate random bytes
     * @return byte array of random bytes
     */
    public static byte[] generateRandomBytes(int size) {
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] arr = new byte[size];
        randomSecureRandom.nextBytes(arr);
        return arr;
    }

    /**
     * A method to encrypt a file
     * @param file - file to encrypt
     * @param key - key to encrypt with
     * @param isSessionKey - if the key is session key
     * @return encrypted file and metadata
     */
    public static String encryptFile(File file, String key, boolean isSessionKey) {
        try {
            byte[] keyBytes = isSessionKey ? ByteManipulation.hexToBytes(key) : generateKey(key);
            byte[] ivBytes = generateRandomBytes(IV_NONCE_SIZE);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] encryptedIpPort = cipher.doFinal(convertByteBufferToByteArray(utf8.encode(conf.getIp() + COLON + conf.getPort())));
            byte[] encryptedFileName = cipher.doFinal(convertByteBufferToByteArray(utf8.encode(file.getName())));
            byte[] encryptedFile = cipher.doFinal( Base64.getEncoder().encode(Files.readAllBytes(file.toPath())));
            String hmacDigest = calcHmacSha256Digest(ivBytes, encryptedFile);
            return ByteManipulation.bytesToHex(encryptedIpPort) +
                    SEPARATOR + ByteManipulation.bytesToHex(encryptedFileName) +
                    SEPARATOR + ByteManipulation.bytesToHex(encryptedFile) +
                    SEPARATOR + ByteManipulation.bytesToHex(ivBytes) +
                    SEPARATOR + hmacDigest;
        } catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return "";
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
     * A method to calc hmac digest
     * @param data - data to calc on
     * @return data digest
     */
    public static String calcHmacSha256Digest(String data)
    {
       return calcHmacSha256Digest(null, convertByteBufferToByteArray(utf8.encode(data)));
    }

    /**
     * A method to decrypt a file
     * @param encryptedFile - file to decrypt
     * @param sessionKey - the session key
     * @return decrypted file with metadata
     */
    public static Pair<String, byte[]> decryptFile(String encryptedFile, String sessionKey) {
        try {
            String[] tokens = encryptedFile.split(SEPARATOR);
            byte[] keyBytes = ByteManipulation.hexToBytes(sessionKey);
            byte[] encryptedIpPortBytes = ByteManipulation.hexToBytes(tokens[0]);
            byte[] encryptedFileNameBytes = ByteManipulation.hexToBytes(tokens[1]);
            byte[] encryptedFileBytes = ByteManipulation.hexToBytes(tokens[2]);
            byte[] ivBytes = ByteManipulation.hexToBytes(tokens[3]);
            String hmacDigest = tokens[4];
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            String hmacResult = hmacDigest.equals(calcHmacSha256Digest(ivBytes, encryptedFileBytes)) ? "true" : "false";
            String ipPort = utf8.decode(ByteBuffer.wrap(cipher.doFinal(encryptedIpPortBytes))).toString();
            String fileName = utf8.decode(ByteBuffer.wrap(cipher.doFinal(encryptedFileNameBytes))).toString();
            byte[] decryptedFile = Base64.getDecoder().decode(cipher.doFinal(encryptedFileBytes));
            return new Pair<>(ipPort + SLASH + hmacDigest + SLASH + hmacResult + SLASH + tokens[3] + SLASH + fileName, decryptedFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * A method to encrypt a message
     * @param message - message to decrypt
     * @param key - key to encrypt with
     * @param isSessionKey - if the key is session key
     * @return encrypted message
     */
    public static String encryptMessage(String message, String key, boolean isSessionKey) {
        try {
            byte[] keyBytes = isSessionKey ? ByteManipulation.hexToBytes(key) : generateKey(key);
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
     * A method to decrypt a message
     * @param message - message to decrypt
     * @param key - key to encrypt with
     * @param isSessionKey - if the key is sessions key
     * @return decrypted message
     */
    public static Map<SecurityToken, String> decryptMessage(String message, String key, boolean isSessionKey) {
        try {
            Map<SecurityToken, String> result = new HashMap<>();
            byte[] keyBytes = isSessionKey ? ByteManipulation.hexToBytes(key) : generateKey(key);
            String[] messageAndIV = message.trim().split(SEPARATOR);
            String hmacDigest = messageAndIV[2];
            byte[] encryptedMessage = ByteManipulation.hexToBytes(messageAndIV[0]);
            byte[] ivBytes = ByteManipulation.hexToBytes(messageAndIV[1]);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            byte[] plainText = cipher.doFinal(encryptedMessage);
            ByteBuffer buffer = ByteBuffer.wrap(plainText);
            result.put(SecurityToken.DECRYPTED_MESSAGE, utf8.decode(buffer).toString().trim());
            result.put(SecurityToken.IV, messageAndIV[1]);
            String hmacResult = hmacDigest.equals(calcHmacSha256Digest(ivBytes, encryptedMessage)) ? "true" : "false";
            result.put(SecurityToken.HMAC_RESULT, hmacResult);
            result.put(SecurityToken.HMAC_DIGEST, hmacDigest);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
        if(a == null)
            return b;
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
