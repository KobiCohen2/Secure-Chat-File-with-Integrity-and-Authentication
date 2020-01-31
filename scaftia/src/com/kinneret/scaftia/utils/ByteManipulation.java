package com.kinneret.scaftia.utils;

import java.nio.ByteBuffer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class ByteManipulation {
    /**
     * Write a byte buffer to a string (space delimited)
     * @param bytesToWrite A ByteBuffer with bytes to write out
     * @return The bytes of the array with space delimiters
     */
    public static String bytesToString(ByteBuffer bytesToWrite) {
        String sb = IntStream.range(0, bytesToWrite.limit()).mapToObj(i -> bytesToWrite.get(i) + " ").collect(Collectors.joining());
        return sb.trim();
    }

    /**
     * Converts a byte array to a hexadecimal string representation
     * @param array The byte array to write out
      * @return The bytes of the array in hexadecimal notation
     */
    public static String bytesToHex (byte[] array)
    {
        String sb = IntStream.range(0, array.length).mapToObj(i -> String.format("%02X", array[i])).collect(Collectors.joining());
        return sb;
    }

    /**
     * Converts a hexademical string to a byte array.
     * @param s A hexadecimal string to convert to byte array
     * @return The byte array representation of the string
     * @throws IllegalArgumentException If the array (after trimming) doesn't have an even number of characters
     * @implNote https://stackoverflow.com/a/140861
     */
    public static byte[] hexToBytes (String s)
    {
        String trimmed = s.trim();
        if (trimmed.length() % 2 != 0)
        {
            throw new IllegalArgumentException("Must provide an even number of characters in the hex string");
        }
        byte[] bytes = new byte[trimmed.length() / 2];
        for (int i = 0; i < trimmed.length(); i += 2)
        {
            bytes[i / 2] = (byte) ((Character.digit(trimmed.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return bytes;
    }



    /**
     * Write a byte buffer to a string (space delimited)
     * @param array A byte array to write out
     * @return The bytes of the array with space delimiters
     */
    public static String bytesToString(byte[] array) {
        StringBuilder sb = new StringBuilder();
        IntStream.range(0, array.length).forEach(i -> {
            sb.append(array[i] + " ");
        });
        return sb.toString().trim();
    }

    /**
     * Converts a string of bytes delimited by spaces into a byte array.  Any illegal or non-byte words are ignored.
     * @param s The string of bytes with space delimiting
     * @return A byte[] with the bytes from the string in it
     */
    public static byte[] stringToBytes(String s)
    {
        String[] parts = s.split(" ");
        byte[] bytesWorking = new byte[parts.length];
        int totalBytes = 0;
        for (int i = 0; i < parts.length; i++)
        {
            try {
                bytesWorking[totalBytes] = Byte.parseByte(parts[i]);
                totalBytes++;
            } catch (Exception ex) {
                System.err.println("Error parsing byte: " + parts[i] + ": " + ex.getMessage());
            }
        }
        // if there are no bytes here, just give back nothing
        if ( totalBytes < 0)
        {
            return new byte[0];
        }
        byte[] bytesFinal = new byte[totalBytes];
        System.arraycopy(bytesWorking, 0, bytesFinal, 0, bytesFinal.length);
        return bytesFinal;
    }

    /**
     * Converts a ByteBuffer to a byte[]
     * @param buff The ByteBuffer to extract the bytes from
     * @return The bytes in an array.
     */
    public static byte[] byteBufferToArray (ByteBuffer buff)
    {
        byte[] array = new byte[buff.limit()];
        try {
            buff.get(array);
        }
        catch (Exception ex)
        {
            array = buff.array();
        }
        return array;
    }
}
