package com.kinneret.scaftia.client;

import com.kinneret.scaftia.configuration.Configuration;
import com.kinneret.scaftia.security.Security;
import com.kinneret.scaftia.server.Server;
import com.kinneret.scaftia.ui.Controller;
import com.kinneret.scaftia.ui.Main;
import com.kinneret.scaftia.utils.ByteManipulation;
import com.kinneret.scaftia.utils.Logger;
import javafx.application.Platform;
import javafx.scene.control.Alert;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.util.Map;

import static com.kinneret.scaftia.security.Security.*;
import static com.kinneret.scaftia.ui.Controller.conf;
import static com.kinneret.scaftia.utils.CommonChars.*;
import static com.kinneret.scaftia.utils.Logger.writeAuthErrorToLog;

/**
 * A class represent listener for the auth server
 */
public class AuthServerResponseListener extends Thread {

    private Socket socket;
    private int port;
    private String nonce;
    private File file;
    private String recipientName;
    private boolean tokenToWrongUser;
    public boolean stop = false;

    /**
     * Constructor
     *
     * @param socket
     */
    public AuthServerResponseListener(Socket socket, int port, String nonce, File file, String recipientName, boolean tokenToWrongUser) {
        this.socket = socket;
        this.port = port;
        this.nonce = nonce;
        this.file = file;
        this.recipientName = recipientName;
        this.tokenToWrongUser = tokenToWrongUser;
    }

    /**
     * A method that the thread will run when starts
     * This method listen for incoming messages from the server
     */
    @Override
    public void run() {
        String authResponse = "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            while (!stop) {
                authResponse = br.readLine();
                if (authResponse != null && !authResponse.isEmpty()) {
                    try {
                        Map<Security.SecurityToken, String> decryptedError = decryptMessage(authResponse, conf.getPassword(), false);
                        String error = decryptedError.get(SecurityToken.DECRYPTED_MESSAGE);
                        if (error.contains("Invalid")) {
                            Platform.runLater(() -> Main.controller.showMessageBox("Error", "server return with error - " + error, Alert.AlertType.ERROR));
                            writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, "server return with error - " + error, null, "",
                                    decryptedError.get(SecurityToken.IV), decryptedError.get(SecurityToken.HMAC_DIGEST), true);
                            this.stop = true;
                            return;
                        }
                    } catch (Exception e){ /* nothing to do*/}
                    Map<Security.SecurityToken, String> decryptedResponse = decryptMessage(authResponse, conf.getAuthPassword(), false);
                    String errorMessage;
                    if (decryptedResponse != null) {
                        String decryptedMessage = decryptedResponse.get(Security.SecurityToken.DECRYPTED_MESSAGE);
                        String[] tokens = decryptedMessage.split(space);
                        String sessionKey;
                        String receivedNonce;
                        String recipient;
                        String recipientToken;
                        try {
                            sessionKey = tokens[0];
                            receivedNonce = tokens[1];
                            recipient = tokens[2];
                            recipientToken = tokens[3];
                        } catch (Exception e) {
                            errorMessage = "Received invalid response from the server, probably due to different auth password";
                            Platform.runLater(() -> Main.controller.showMessageBox("Error",
                                    errorMessage, Alert.AlertType.ERROR));
                            writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, decryptedMessage,
                                    decryptedResponse.get(SecurityToken.IV), decryptedResponse.get(SecurityToken.HMAC_DIGEST), true);
                            this.stop = true;
                            return;
                        }
                        if (!nonce.equals(receivedNonce)) //Alice nonce check
                        {
                            errorMessage = "Received invalid response from the server, probably due to wrong nonce or wrong requestor key";
                            Platform.runLater(() -> Main.controller.showMessageBox("Error", errorMessage, Alert.AlertType.ERROR));
                            writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, decryptedMessage,
                                    decryptedResponse.get(SecurityToken.IV), decryptedResponse.get(SecurityToken.HMAC_DIGEST), true);
                            this.stop = true;
                            return;
                        } else if (!recipient.equalsIgnoreCase(recipientName) && !tokenToWrongUser) {
                            errorMessage = "Received wrong recipient (" + recipient + ") from the server";
                            Platform.runLater(() -> Main.controller.showMessageBox("Error", errorMessage, Alert.AlertType.ERROR));
                            writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, decryptedMessage,
                                    decryptedResponse.get(SecurityToken.IV), decryptedResponse.get(SecurityToken.HMAC_DIGEST), true);
                            this.stop = true;
                            return;
                        }
                        Configuration.Neighbor neighbor = conf.getNeighborByName(recipientName);

                        Socket fileSocket = new Socket(neighbor.getIp(), port);
                        FileClientListener fileClientListener = new FileClientListener(fileSocket, sessionKey, file);
                        fileClientListener.start();
                        try {
                            PrintWriter pw = new PrintWriter(fileSocket.getOutputStream());
                            String tokenToSend = Main.controller.rbtRandomToken.isSelected() ?
                                    ByteManipulation.bytesToHex(Security.generateRandomBytes(recipientToken.length())) : recipientToken;
                            pw.write(encryptMessage(Server.MessageType.TOKEN.name() + space + tokenToSend, conf.getPassword(),
                                    false) + newLine);
                            pw.flush();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        this.stop = true;
                    } else {
                        errorMessage = "Received invalid response from the server, probably due to different auth password";
                        Platform.runLater(() -> Main.controller.showMessageBox("Error",
                                errorMessage, Alert.AlertType.ERROR));
                        writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, "decryption error - can't decrypt message",
                                "", "", true);
                        this.stop = true;
                        return;
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
