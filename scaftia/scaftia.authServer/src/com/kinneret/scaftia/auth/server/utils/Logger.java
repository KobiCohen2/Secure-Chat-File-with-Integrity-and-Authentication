package com.kinneret.scaftia.auth.server.utils;

import com.kinneret.scaftia.auth.server.configuration.Configuration;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static com.kinneret.scaftia.auth.server.utils.CommonChars.space;
import static com.kinneret.scaftia.auth.server.utils.DateAndTime.getCurrentDateTimeStamp;

public class Logger {

    private static File logger;

    static {
        logger = new File("SCAFTIA-AuthServer-Logger.log");
    }

    /**
     * An enum that contains log level types
     */
    public enum LOG_LEVEL {
        INFO,
        DEBUG,
        ERROR
    }

    /**
     * A method to write info to log file
     * @param TAG
     * @param errorMessage
     * @param sender
     * @param recipient
     * @param message
     * @param nonce
     * @param isEncrypted
     * @param isHmacValid
     * @param isResponse
     * @param responseInfo
     */
    public static void writeToLog(LOG_LEVEL TAG, String errorMessage, Configuration.User sender, Configuration.User recipient, String message,
                                  String nonce, boolean isEncrypted, boolean isHmacValid, boolean isResponse, String responseInfo) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(logger, true))) {

            String senderIpPort = sender == null ? "received unknown sender" : sender.getIp() + ":" + sender.getPort();
            String senderName = sender == null ? "received unknown sender" : sender.getName();
            String recipientName = recipient == null ? "received unknown recipient" : recipient.getName();
            bw.write(getCurrentDateTimeStamp() + space + TAG + " - sender's ip and port: " + senderIpPort +
                    ", sender's name: " + senderName + ", recipient's name: " + recipientName +
                    ", nonce: " + nonce + ", is request message encrypted: " + isEncrypted + ", is HMAC valid: " + isHmacValid + ", message: " + message +
                    ", error message: " + errorMessage + ", is response sent back: " + isResponse +
                    ", is response sent back was intentionally incorrect: " + responseInfo + "\n");
            bw.newLine();
        } catch (IOException e) {
            System.out.println("Error while writing to log");
        }
    }
}
