package com.kinneret.scaftia.client;

import com.kinneret.scaftia.configuration.Configuration;
import com.kinneret.scaftia.server.Server;
import com.kinneret.scaftia.ui.Controller;
import com.kinneret.scaftia.utils.Logger;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.kinneret.scaftia.security.Security.encryptMessage;
import static com.kinneret.scaftia.server.Server.MessageType.*;
import static com.kinneret.scaftia.ui.Controller.conf;
import static com.kinneret.scaftia.utils.CommonChars.*;
import static com.kinneret.scaftia.utils.Logger.writeToLog;

/**
 * A class represent client
 */
public class Client {

    /**
     * A map to hold the open socket for each neighbor in the multi-cast
     */
    public static Map<Configuration.Neighbor, Socket> connectedNeighborsMap = Collections.synchronizedMap(new HashMap<>());

    /**
     *A method to send messages to all neighbors in the multi-cast
     * @param type - the type of the message
     * @param message - the content of the message
     */
    public static void sendToNeighbors(Server.MessageType type, String message) {
        String encryptedMessage;
        String iv = "";
        String hmac = "";
        for (Socket socket: connectedNeighborsMap.values()) {
            try {
                PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
                switch (type) {
                    case HELLO:
                        encryptedMessage = encryptMessage(HELLO + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort(), conf.getPassword(), false);
                        iv = encryptedMessage.split(SEPARATOR)[1];
                        hmac = encryptedMessage.split(SEPARATOR)[2];
                        printWriter.write(encryptedMessage + newLine);
                        break;
                    case MESSAGE:
                        encryptedMessage = encryptMessage(MESSAGE + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort() + space + message, conf.getPassword(), false);
                        iv = encryptedMessage.split(SEPARATOR)[1];
                        hmac = encryptedMessage.split(SEPARATOR)[2];
                        printWriter.write(encryptedMessage + newLine);
                        break;
                    case BYE:
                        encryptedMessage = encryptMessage(BYE + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort(), conf.getPassword(), false);
                        iv = encryptedMessage.split(SEPARATOR)[1];
                        hmac = encryptedMessage.split(SEPARATOR)[2];
                        printWriter.write(encryptedMessage + newLine);
                        break;
                }
                printWriter.flush();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, type, message, iv, hmac);
    }

    /**
     * A method to send messages to specific neighbor in the multi-cast
     * @param type - the type of the message
     * @param message - the content of the message
     * @param neighbor - the neighbor to whom the message will be sent
     */
    public static void sendToNeighbor(Server.MessageType type, String message, Configuration.Neighbor neighbor)
    {
        String encryptedMessage;
        String iv = "";
        String hmac = "";
            try {
                PrintWriter printWriter = new PrintWriter(connectedNeighborsMap.get(neighbor).getOutputStream());
                encryptedMessage = encryptMessage(type + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort() + space + message, conf.getPassword(), false);
                iv = encryptedMessage.split(SEPARATOR)[1];
                hmac = encryptedMessage.split(SEPARATOR)[2];
                printWriter.write(encryptedMessage + newLine);
                printWriter.flush();
            } catch (Exception e) {
                e.printStackTrace();
        }
        writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, type, message, iv, hmac);
    }

    /**
     * A method to send file request message to specific neighbor in the multi-cast
     * @param neighbor - the neighbor to whom the message will be sent
     * @param fileName - the name of the file
     */
    public static void sendFileRequestToNeighbor(Configuration.Neighbor neighbor, String fileName) {
        Socket socket = connectedNeighborsMap.get(neighbor);
        try {
            PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
            String encryptedMessage = encryptMessage(SENDFILE + space + Controller.userName +
                    space + conf.getIp() + space + conf.getPort() + space + fileName, conf.getPassword(), false);
            printWriter.write(encryptedMessage + newLine);
            printWriter.flush();
            writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, SENDFILE, fileName,
                    encryptedMessage.split(SEPARATOR)[1], encryptedMessage.split(SEPARATOR)[2]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to start client
     */
    public static void connectClient() {
        conf.getNeighbors().forEach(neighbor -> {
            try {
                Socket socket = new Socket(neighbor.getIp(), Integer.parseInt(neighbor.getPort()));
                PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
                String message = HELLO + space + Controller.userName + space + conf.getIp() + space + conf.getPort();
                String encryptedMessage = encryptMessage(message, conf.getPassword(), false);
                printWriter.write(encryptedMessage + newLine);
                printWriter.flush();
                writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, HELLO, message,
                        encryptedMessage.split(SEPARATOR)[1], encryptedMessage.split(SEPARATOR)[2]);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        Controller.isConnected = true;
    }

    /**
     * A method to disconnect client
     */
    public static void disconnectClient() {
       connectedNeighborsMap.values().forEach(socket -> {
           try {
               socket.close();
           } catch (IOException e) {
               e.printStackTrace();
           }
       });
       connectedNeighborsMap.clear();
    }
}