package com.kinneret.scaftia.server.files;

import com.kinneret.scaftia.client.Client;
import com.kinneret.scaftia.configuration.Configuration;
import com.kinneret.scaftia.security.Security;
import com.kinneret.scaftia.server.Server;
import com.kinneret.scaftia.ui.Controller;
import com.kinneret.scaftia.ui.Main;
import com.kinneret.scaftia.utils.ByteManipulation;
import com.kinneret.scaftia.utils.Logger;
import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.util.Pair;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.kinneret.scaftia.security.Security.*;
import static com.kinneret.scaftia.server.HandleClientThread.concatenateContentBack;
import static com.kinneret.scaftia.server.HandleClientThread.getNeighborByIpPort;
import static com.kinneret.scaftia.server.Server.MessageType.*;
import static com.kinneret.scaftia.ui.Controller.conf;
import static com.kinneret.scaftia.utils.CommonChars.*;
import static com.kinneret.scaftia.utils.Logger.writeAuthErrorToLog;
import static com.kinneret.scaftia.utils.Logger.writeToLog;

/**
 * A class represented a thread that listen to the client files
 */
public class HandleFileTransferThread extends Thread {

    private Socket clientSocket;
    private Configuration.Neighbor sender;
    private boolean stop = false;
    private Configuration.Neighbor neighbor;
    private AtomicBoolean succeed = new AtomicBoolean(false);
    private boolean isIntegrityOk;
    private String nonce;
    private String sessionKey;

    HandleFileTransferThread(Socket socket, Configuration.Neighbor sender) {
        this.clientSocket = socket;
        this.sender = sender;
    }

    /**
     * A method that the thread will run when starts
     */
    @Override
    public void run() {
        System.out.println("Received connection from: " + clientSocket);
        try (InputStream in = clientSocket.getInputStream();
             BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
            String input;

            while (!stop) {
                input = br.readLine();
                if ((input != null) && (!input.trim().isEmpty()) && (!stop)) {
                    processMessage(input);
                }
            }
            if (succeed.get()) {
                Client.sendToNeighbor(ACK, Controller.userName + " Received the file successfully", neighbor);
            } else {
                if (isIntegrityOk) {
                    Client.sendToNeighbor(OK, Controller.userName + " Canceled file saving after receiving it", neighbor);
                } else {
                    if (neighbor != null)
                        Client.sendToNeighbor(FAILED, Controller.userName + " Did not receive the file, because the file is corrupted", neighbor);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to process an incoming encrypted file
     * @param encryptedMessage - the encrypted file to process
     */
    private void processMessage(String encryptedMessage) {
        Map<Security.SecurityToken, String> decryptedMessage = decryptMessage(encryptedMessage, conf.getPassword(), false);
        String message = decryptedMessage.get(Security.SecurityToken.DECRYPTED_MESSAGE);
        String[] messageTokens = message.split(space);
        Server.MessageType type = Server.MessageType.valueOf(messageTokens[0].toUpperCase());
        Map<Security.SecurityToken, String> decryptedContent;
        switch (type) {
            case TOKEN:
                String tokenError = "Received invalid token";
                String messageBack = "You sent me an invalid token";
                decryptedContent = decryptMessage(messageTokens[1], conf.getAuthPassword(), false);
                if (decryptedContent != null) {
                    String token = decryptedContent.get(Security.SecurityToken.DECRYPTED_MESSAGE);
                    String[] splitToken = token.split(space);
                    String sender;
                    try {
                        sessionKey = splitToken[0];
                        sender = splitToken[1];
                    } catch (Exception e) {
                        sendFailedMessage(decryptedContent, messageTokens[1], tokenError, messageBack, false);
                        return;
                    }
                    Configuration.Neighbor neighbor = conf.getNeighborByName(sender);
                    if (neighbor == null) {
                        sendFailedMessage(decryptedContent, messageTokens[1], token, messageBack, false);
                        return;
                    }
                    nonce = ByteManipulation.bytesToHex(Security.generateRandomBytes(IV_NONCE_SIZE));
                    String challenge = Main.controller.rbtWrongKeyNonce.isSelected() ?
                            encryptMessage(nonce, UUID.randomUUID().toString(), false) :
                            encryptMessage(nonce, sessionKey, true);
                    try {
                        PrintWriter pw = new PrintWriter(clientSocket.getOutputStream());
                        pw.write(encryptMessage(Server.MessageType.CHALLENGE + space + challenge, conf.getPassword(), false) + newLine);
                        pw.flush();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    sendFailedMessage(decryptedContent, messageTokens[1], tokenError, messageBack, false);
                    return;
                }
                break;
            case RESPONSE:
                decryptedContent = null;
                try {
                    decryptedContent = decryptMessage(messageTokens[1], sessionKey, true);
                } catch (Exception e) {
                    Platform.runLater(() -> Main.controller.showMessageBox("Error", "Received response encrypted with wrong key", Alert.AlertType.ERROR));
                    sendFailedMessage(decryptedContent, messageTokens[1], "Received response encrypted with wrong key", "You sent me invalid response", false);
                    return;
                }
                if (decryptedContent != null) {
                    String receivedNonce = decryptedContent.get(Security.SecurityToken.DECRYPTED_MESSAGE);
                    if (checkNonce(receivedNonce)) {
                        try {
                            PrintWriter pw = new PrintWriter(clientSocket.getOutputStream());
                            pw.write(encryptMessage(Server.MessageType.OK + space + encryptMessage(OK.name(), sessionKey, true),
                                    conf.getPassword(), false) + newLine);
                            pw.flush();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        Platform.runLater(() -> Main.controller.showMessageBox("Error", "Received wrong numerical response", Alert.AlertType.ERROR));
                        sendFailedMessage(decryptedContent, messageTokens[1], "Received wrong numerical response", "You sent me wrong numerical response", false);
                        return;
                    }
                }
                break;
            case FILE:
                Pair<String, byte[]> decryptedFile = decryptFile(messageTokens[1], sessionKey);
                if (decryptedFile == null) {
                    sendFailedMessage(null, messageTokens[1], "Received file encrypted with wrong key", "The file was not successfully received, encrypted with wrong key", true);
                    return;
                }
                String[] tokens = decryptedFile.getKey().trim().split(SLASH);
                String[] ipPort = tokens[0].trim().split(COLON);
                String hmacDigest = tokens[1].trim();
                String hmacResult = tokens[2].trim();
                String iv = tokens[3].trim();
                String fileName = tokens[4].trim();
                isIntegrityOk = hmacResult.equals("true");
                neighbor = getNeighborByIpPort(ipPort[0], ipPort[1]);

                if (!isIntegrityOk) {
                    succeed.set(false);
                    stop = true;
                    Platform.runLater(() ->
                            Main.controller.showMessageBox("File Transfer",
                                    "File transfer completed successfully, but the file is illegal or corrupted", Alert.AlertType.ERROR));
                    writeToLog(Logger.LOG_LEVEL.ERROR, "Integrity error, probably due to corrupted file or wrong mac key.",
                            neighbor, neighbor.getName(), null, "", iv, hmacDigest);
                    return;
                }

                Platform.runLater(() -> {
                    File receivedFile = Main.controller.chooseDirectory(fileName);
                    if (receivedFile != null) {
                        try (FileOutputStream fos = new FileOutputStream(receivedFile)) {
                            fos.write(decryptedFile.getValue());
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        Main.controller.showMessageBox("File Transfer", "File transfer completed successfully", Alert.AlertType.INFORMATION);
                        succeed.set(true);
                    }
                    try {
                        PrintWriter pw = new PrintWriter(clientSocket.getOutputStream());
                        pw.write(encryptMessage(ACK + space + encryptMessage("File received successfully", sessionKey, true),
                                conf.getPassword(), false) + newLine);
                        pw.flush();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    stop = true;
                    Server.stopFileServerThread(neighbor);
                });
                break;
            case FAILED:
                Platform.runLater(() -> Main.controller.showMessageBox("Error", concatenateContentBack(messageTokens, 1), Alert.AlertType.ERROR));
                this.stop = true;
                Server.stopFileServerThread(neighbor);
                break;
        }
    }

    private void sendFailedMessage(Map<SecurityToken, String> decryptedContent, String response, String errorMessage, String messageBack, boolean isFile) {
        Platform.runLater(() -> Main.controller.showMessageBox("Error", errorMessage, Alert.AlertType.ERROR));

        String content, iv, hmac;
        if (decryptedContent == null) {
            String[] tokens = response.split(SEPARATOR);
            try {
                content = tokens[isFile ? 2 : 0];
                iv = tokens[isFile ? 3 : 1];
                hmac = tokens[isFile ? 4 : 2];
            } catch (Exception e)
            {
                content = iv = hmac = "decryption failure";
            }
        } else {
            content = decryptedContent.get(SecurityToken.DECRYPTED_MESSAGE);
            iv = decryptedContent.get(SecurityToken.IV);
            hmac = decryptedContent.get(SecurityToken.HMAC_DIGEST);
        }
        writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, errorMessage, sender, content, iv, hmac, false);
        try {
            PrintWriter pw = new PrintWriter(clientSocket.getOutputStream());
            pw.write(encryptMessage(FAILED + space + messageBack,
                    conf.getPassword(), false) + newLine);
            pw.flush();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        Server.stopFileServerThread(neighbor);
        this.stop = true;
    }

    private boolean checkNonce(String receivedNonce) {
        BigInteger receivedNonceBytes = new BigInteger(ByteManipulation.hexToBytes(receivedNonce));
        BigInteger nonceBytes = new BigInteger(ByteManipulation.hexToBytes(nonce));
        return nonceBytes.subtract(BigInteger.ONE).equals(receivedNonceBytes);
    }
}
