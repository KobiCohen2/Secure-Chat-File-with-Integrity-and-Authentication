package com.kinneret.scaftia.utils;

import com.kinneret.scaftia.configuration.Configuration;
import com.kinneret.scaftia.server.Server;
import com.kinneret.scaftia.ui.Controller;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static com.kinneret.scaftia.ui.Controller.conf;
import static com.kinneret.scaftia.utils.CommonChars.space;
import static com.kinneret.scaftia.utils.DateAndTime.getCurrentDateTimeStamp;

public class Logger {

    private static File logger;

    static {
        logger = new File("SCAFTIA-Logger.log");
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
     *
     * @param TAG
     * @param errorMessage
     * @param neighbor
     * @param userName
     * @param type
     * @param message
     * @param iv
     * @param hmac
     */
    public static void writeToLog(LOG_LEVEL TAG, String errorMessage, Configuration.Neighbor neighbor, String userName, Server.MessageType type, String message,
                                  String iv, String hmac) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(logger, true))) {
            if (type == null)//error in decryption or integrity
            {
                bw.write(getCurrentDateTimeStamp() + space + TAG + " - " + "Received Message - " +
                        errorMessage + " content: " + message + ", iv: " + iv + ", hmac: " + hmac + ", valid: FALSE" + "\n");
                bw.newLine();
            } else {
                if (neighbor == null) {
                    bw.write(getCurrentDateTimeStamp() + space + TAG + " - " + "Sent Message - " + "ip: " + conf.getIp() +
                            ", port: " + conf.getPort() + ", name: " + userName + " (me) " + ", type: " + type +
                            ", message: " + message + ", iv: " + iv + ", hmac: " + hmac + ", valid: TRUE" + "\n");
                    bw.newLine();
                } else {
                    bw.write(getCurrentDateTimeStamp() + space + TAG + " - " + "Received Message - " + "ip: " + neighbor.getIp() +
                            ", port: " + neighbor.getPort() + ", name: " + userName + ", type: " + type +
                            ", message: " + message + ", iv: " + iv + ", hmac: " + hmac + ", valid: TRUE" + "\n");
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            System.out.println("Error while writing to log");
        }
    }

    /**
     * Write authentication errors to log
     * @param TAG
     * @param errorMessage
     * @param sender
     * @param message
     * @param iv
     * @param hmac
     * @param isSender
     */
    public static void writeAuthErrorToLog(LOG_LEVEL TAG, String errorMessage, Configuration.Neighbor sender, String message,
                                           String iv, String hmac, boolean isSender) {
        String senderIpPort;
        String senderName;
        if(isSender)
        {
            senderIpPort = conf.getIp() + ":" + conf.getPort();
            senderName = Controller.userName;
        }
        else
        {
            senderIpPort = sender == null ? "unknown sender - cant retrieve ip and port" : sender.getIp() + ":" + sender.getPort();
            senderName = sender == null ? "unknown sender" : sender.getName();
        }
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(logger, true))) {
            bw.write(getCurrentDateTimeStamp() + space + TAG + " Auth Error - sender's ip and port: " + senderIpPort +
                    ", sender's name: " + senderName + ", received message or token: " + message + ", iv: " + iv +
                    ", hmac: " + hmac + ", error description: " + errorMessage + "\n");
            bw.newLine();
        } catch (IOException e) {
            System.out.println("Error while writing to log");
        }
    }
}
