package com.kinneret.scaftia.client;

import com.kinneret.scaftia.security.Security;
import com.kinneret.scaftia.server.Server;
import com.kinneret.scaftia.ui.Main;
import com.kinneret.scaftia.utils.ByteManipulation;
import com.kinneret.scaftia.utils.Logger;
import javafx.application.Platform;
import javafx.scene.control.Alert;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.util.Map;
import java.util.UUID;

import static com.kinneret.scaftia.security.Security.*;
import static com.kinneret.scaftia.server.HandleClientThread.concatenateContentBack;
import static com.kinneret.scaftia.ui.Controller.conf;
import static com.kinneret.scaftia.utils.CommonChars.*;
import static com.kinneret.scaftia.utils.Logger.writeAuthErrorToLog;

/**
 * A class represent listener for the file transfer session
 */
public class FileClientListener extends Thread {

    private Socket socket;
    private String sessionKey;
    private File file;
    public boolean stop = false;

    /**
     * Constructor
     * @param socket
     * @param sessionKey
     * @param file
     */
    FileClientListener(Socket socket, String sessionKey, File file) {
        this.socket = socket;
        this.sessionKey = sessionKey;
        this.file = file;
    }

    /**
     * A method that the thread will run when starts
     * This method listen for incoming messages from the server
     */
    @Override
    public void run() {
        String response = "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            while (!stop) {
                response = br.readLine();
                if (response != null && !response.isEmpty()) {
                    Map<Security.SecurityToken, String> decryptedMessage = decryptMessage(response, conf.getPassword(), false);
                    String message = decryptedMessage.get(Security.SecurityToken.DECRYPTED_MESSAGE);
                    String[] messageTokens = message.split(space);
                    Server.MessageType type = Server.MessageType.valueOf(messageTokens[0].toUpperCase());
                    Map<Security.SecurityToken, String> decryptedContent;
                    String errorMessage;
                    switch (type) {
                        case CHALLENGE:
                            try {
                                decryptedContent = decryptMessage(messageTokens[1], sessionKey, true);
                            } catch (Exception e)
                            {
                                errorMessage = "Received nonce encrypted with wrong key";
                                Platform.runLater(() -> Main.controller.showMessageBox("Error", errorMessage, Alert.AlertType.ERROR));
                                String[] parts = messageTokens[1].split(SEPARATOR);
                                writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, parts.length > 0 ? parts[0] : "decryption failure",
                                        parts.length > 1 ? parts[1] : "decryption failure", parts.length > 2 ? parts[2] : "decryption failure", true);
                                try {
                                    PrintWriter pw = new PrintWriter(socket.getOutputStream());
                                    pw.write(encryptMessage(Server.MessageType.FAILED + space + errorMessage,
                                            conf.getPassword(), false)+ newLine);
                                    pw.flush();
                                } catch (Exception e1) {
                                    e1.printStackTrace();
                                }
                                this.stop = true;
                                return;
                            }
                            if (decryptedContent != null) {
                                String receivedNonce = decryptedContent.get(Security.SecurityToken.DECRYPTED_MESSAGE);
                                BigInteger nonce;
                                try {
                                    nonce = new BigInteger(ByteManipulation.hexToBytes(receivedNonce));
                                }catch (Exception e)
                                {
                                    Platform.runLater(() -> Main.controller.showMessageBox("Error", "Received an invalid nonce", Alert.AlertType.ERROR));
                                    writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, "Received an invalid nonce", null, decryptedContent.get(Security.SecurityToken.DECRYPTED_MESSAGE),
                                            decryptedContent.get(SecurityToken.IV), decryptedContent.get(SecurityToken.HMAC_DIGEST), true);
                                    try {
                                        PrintWriter pw = new PrintWriter(socket.getOutputStream());
                                        pw.write(encryptMessage(Server.MessageType.FAILED + space + "You sent me an invalid nonce",
                                                conf.getPassword(), false)+ newLine);
                                        pw.flush();
                                    } catch (Exception e1) {
                                        e1.printStackTrace();
                                    }
                                    this.stop = true;
                                    return;
                                }
                                BigInteger afterSubtract = Main.controller.rbtWrongNumericalResponse.isSelected() ?
                                        nonce.add(BigInteger.ONE) :
                                        nonce.subtract(BigInteger.ONE);
                                String answer = ByteManipulation.bytesToHex(afterSubtract.toByteArray());
                                String challengeResponse = Main.controller.rbtWrongKeyResponse.isSelected() ?
                                        encryptMessage(answer, ByteManipulation.bytesToHex(Security.generateRandomBytes(15)), true) :
                                        encryptMessage(answer, sessionKey, true);
                                try {
                                    PrintWriter pw = new PrintWriter(socket.getOutputStream());
                                    pw.write(encryptMessage(Server.MessageType.RESPONSE + space + challengeResponse,
                                            conf.getPassword(), false)+ newLine);
                                    pw.flush();
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                            else{
                                errorMessage = "Received nonce encrypted with wrong key";
                                Platform.runLater(() -> Main.controller.showMessageBox("Error", errorMessage, Alert.AlertType.ERROR));
                                String[] parts = messageTokens[1].split(SEPARATOR);
                                writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, parts.length > 0 ? parts[0] : "decryption failure",
                                        parts.length > 1 ? parts[1] : "decryption failure", parts.length > 2 ? parts[2] : "decryption failure", true);
                                try {
                                    PrintWriter pw = new PrintWriter(socket.getOutputStream());
                                    pw.write(encryptMessage(Server.MessageType.FAILED + space + errorMessage,
                                            conf.getPassword(), false)+ newLine);
                                    pw.flush();
                                } catch (Exception e1) {
                                    e1.printStackTrace();
                                }
                                this.stop = true;
                                return;
                            }
                            break;
                        case OK:
                            try {
                                String wrongKey = UUID.randomUUID().toString();
                                String encryptedFile = Main.controller.rbtWrongKeyFile.isSelected() ?
                                        encryptFile(file, wrongKey, false) : encryptFile(file, sessionKey, true);
                                PrintWriter pw = new PrintWriter(socket.getOutputStream());
                                pw.write(encryptMessage(Server.MessageType.FILE + space + encryptedFile, conf.getPassword(), false) + newLine);
                                pw.flush();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            break;
                        case FAILED:
                            String error = concatenateContentBack(messageTokens, 1);
                            Platform.runLater(() -> Main.controller.showMessageBox("Error", error, Alert.AlertType.ERROR));
                            writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, "file error", null, error,
                                    decryptedMessage.get(SecurityToken.IV), decryptedMessage.get(SecurityToken.HMAC_DIGEST), true);
                            this.stop = true;
                            break;
                        case ACK:
                            this.stop = true;
                            break;
                    }
                }
            }
        } catch (SocketException e) {
            System.out.println("The server closed the connection");
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Closing connection with " + socket.toString());
        }
    }
}
