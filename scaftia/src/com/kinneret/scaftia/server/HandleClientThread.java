package com.kinneret.scaftia.server;

import com.kinneret.scaftia.client.AuthServerResponseListener;
import com.kinneret.scaftia.client.Client;
import com.kinneret.scaftia.configuration.Configuration;
import com.kinneret.scaftia.security.Security;
import com.kinneret.scaftia.ui.Controller;
import com.kinneret.scaftia.ui.Main;
import com.kinneret.scaftia.utils.ByteManipulation;
import com.kinneret.scaftia.utils.Logger;
import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

import static com.kinneret.scaftia.security.Security.*;
import static com.kinneret.scaftia.server.Server.MessageType.*;
import static com.kinneret.scaftia.ui.Controller.conf;
import static com.kinneret.scaftia.ui.Controller.selectedFile;
import static com.kinneret.scaftia.utils.CommonChars.*;
import static com.kinneret.scaftia.utils.DateAndTime.getCurrentDateTimeStamp;
import static com.kinneret.scaftia.utils.Logger.writeAuthErrorToLog;
import static com.kinneret.scaftia.utils.Logger.writeToLog;

/**
 * A class represented a thread that listen to the client messages
 */
public class HandleClientThread extends Thread {

    private Socket clientSocket;
    boolean stop = false;
    private static final int TOKENS_MIN_LENGTH = 3;

    HandleClientThread(Socket socket) {
        this.clientSocket = socket;
    }

    /**
     * A method that the thread will run when starts
     */
    @Override
    public void run() {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {
            String input;
            while (!stop) {
                input = br.readLine();
                if ((input != null) && (!input.trim().isEmpty()) && (!stop)) {
                    processMessage(input);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to process an encrypted message
     * @param encryptedMessage - the encrypted message to process
     */
    private void processMessage(String encryptedMessage) {
        Map<Security.SecurityToken, String> decryptedMessage = decryptMessage(encryptedMessage, conf.getPassword(), false);
        if (decryptedMessage == null)
            return;
        String iv = decryptedMessage.get(Security.SecurityToken.IV);
        String[] messageTokens = decryptedMessage.get(Security.SecurityToken.DECRYPTED_MESSAGE).split(space);
        String hmacResult = decryptedMessage.get(Security.SecurityToken.HMAC_RESULT);
        String hmacDigest = decryptedMessage.get(Security.SecurityToken.HMAC_DIGEST);
        boolean isBadIntegrity = hmacResult.equals("false");
        if (messageTokens.length < TOKENS_MIN_LENGTH) {
            //error in decryption - not the same public key
            writeToLog(Logger.LOG_LEVEL.ERROR, "Decryption error, probably due to incorrect key.",
                    null, null, null,
                    decryptedMessage.get(Security.SecurityToken.DECRYPTED_MESSAGE), iv, hmacDigest);

            return;
        }
        if (isBadIntegrity && !HELLO.toString().equalsIgnoreCase(messageTokens[0])) {
            badIntegrityMessageDisplayLog(decryptedMessage, iv, hmacDigest);
        }
        String name = messageTokens[1].trim();
        String ip = messageTokens[2].trim();
        String port = messageTokens[3].trim();
        Configuration.Neighbor neighbor;
        String message;
        Server.MessageType type = Server.MessageType.valueOf(messageTokens[0].toUpperCase());
        switch (type) {
            case HELLO:
                neighbor = addClientName(ip, port, name);
                if (isBadIntegrity && !Client.connectedNeighborsMap.containsKey(neighbor)) {
                    badIntegrityMessageDisplayLog(decryptedMessage, iv, hmacDigest);
                }

                if (!isBadIntegrity && !Client.connectedNeighborsMap.containsKey(neighbor)) {
                    String neighborListViewItem = ip + COLON + port + " - " + name;
                    Platform.runLater(() -> {
                        if (!Main.controller.lvNeighbors.getItems().contains(neighborListViewItem)) {
                            Main.controller.lvNeighbors.getItems().add(neighborListViewItem);
                            Main.controller.tbChat.appendText(getCurrentDateTimeStamp() + space +
                                    name + " joined the conversation" + newLine);
                        }
                    });
                    writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, decryptedMessage.get(Security.SecurityToken.DECRYPTED_MESSAGE), iv, hmacDigest);
                }
                try {
                    if (!Client.connectedNeighborsMap.containsKey(neighbor)) {
                        Socket socket = new Socket(ip, Integer.parseInt(port));
                        PrintWriter pw = new PrintWriter(socket.getOutputStream());
                        pw.write(encryptMessage(HELLO + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort(), conf.getPassword(), false) + newLine);
                        pw.flush();
                        Client.connectedNeighborsMap.put(neighbor, socket);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case MESSAGE:
                if (isBadIntegrity)
                    return;
                //concatenate content back
                message = concatenateContentBack(messageTokens, 4);
                neighbor = getNeighborByIpPort(ip, port);
                Platform.runLater(() -> Main.controller.tbChat.appendText(getCurrentDateTimeStamp() + space + name + ": " + message + newLine));
                writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, message, iv, hmacDigest);
                break;
            case SENDFILE:
                if (isBadIntegrity)
                    return;
                //concatenate content back
                String fileName = concatenateContentBack(messageTokens, 4);
                message = name + " wants to send you a file called " + fileName + "\n Are you want to receive it?";
                neighbor = getNeighborByIpPort(ip, port);
                writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, message, iv, hmacDigest);
                final boolean[] answer = {false};
                Platform.runLater(() -> {
                    Alert alert = Main.controller.showMessageBox("File Transfer", message,
                            Alert.AlertType.INFORMATION, ButtonType.YES, ButtonType.NO);
                    Optional<ButtonType> result = alert.showAndWait();
                    answer[0] = ButtonType.YES == result.get();

                    if (answer[0]) {
                        int filePort = generatePort();
                        Server.startFileServerThread(neighbor, filePort);
                        Client.sendToNeighbor(OK, Controller.userName + " accepted to receive the file-" + filePort, neighbor);

                    } else {
                        Client.sendToNeighbor(NO, Controller.userName + " refused to receive the file", neighbor);
                        Platform.runLater(() -> Main.controller.showMessageBox("File Transfer - Refusal",
                                "File refusal acknowledgment", Alert.AlertType.INFORMATION));
                    }
                });
                break;
            case OK:
                if (isBadIntegrity)
                    return;
                message = concatenateContentBack(messageTokens, 4);
                int filePort = Integer.parseInt(message.split(SEPARATOR)[1]);
                String splitedMessage = message.split(SEPARATOR)[0];
                neighbor = getNeighborByIpPort(ip, port);
                Platform.runLater(() -> Main.controller.showMessageBox("File Transfer - Acceptance",
                        splitedMessage, Alert.AlertType.INFORMATION));
                if (message.contains("accepted")) {

                    try {
                        boolean tokenToWrongUser = !Main.controller.tbTokenWrongUser.getText().isEmpty();
                        Socket authSocket = new Socket(conf.getAuthServerIp(), Integer.parseInt(conf.getAuthServerPort()));
                        String nonce = ByteManipulation.bytesToHex(Security.generateRandomBytes(IV_NONCE_SIZE));
                        AuthServerResponseListener authServerResponseListener =
                                new AuthServerResponseListener(authSocket, filePort, nonce, selectedFile, neighbor.getName(), tokenToWrongUser);
                        authServerResponseListener.start();
                        try {
                            PrintWriter pw = new PrintWriter(authSocket.getOutputStream());
                            String requestor = Main.controller.tbRequestorName.getText().isEmpty() ? Controller.userName : Main.controller.tbRequestorName.getText();
                            String receiver = Main.controller.tbReceiverName.getText().isEmpty() ? neighbor.getName() : Main.controller.tbReceiverName.getText();
                            receiver = Main.controller.tbTokenWrongUser.getText().isEmpty() ? receiver : Main.controller.tbTokenWrongUser.getText();
                            String request = requestor + space + receiver + space + nonce;
                            String digest = calcHmacSha256Digest(request);
                            pw.write(request + space + digest + newLine);
                            pw.flush();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } catch (Exception e) {
                        Platform.runLater(() -> Main.controller.showMessageBox("ERROR",
                                "The auth server is off", Alert.AlertType.ERROR));
                        writeAuthErrorToLog(Logger.LOG_LEVEL.ERROR, "auth server error", null, "the auth server is off",
                               "-" , "-", true);
                        e.printStackTrace();
                    }
                    //new Thread(() -> Client.sendFileToNeighbor(neighbor, selectedFile)).start();
                }
                writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, message, iv, hmacDigest);
                break;
            case NO:
                if (isBadIntegrity)
                    return;
                message = concatenateContentBack(messageTokens, 4);
                neighbor = getNeighborByIpPort(ip, port);
                Platform.runLater(() -> Main.controller.showMessageBox("File Transfer - Refusal",
                        message, Alert.AlertType.INFORMATION));
                writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, message, iv, hmacDigest);
                break;
            case ACK:
                if (isBadIntegrity)
                    return;
                message = concatenateContentBack(messageTokens, 4);
                neighbor = getNeighborByIpPort(ip, port);
                Platform.runLater(() -> Main.controller.showMessageBox("File Transfer - Received Successfully",
                        message, Alert.AlertType.INFORMATION));
                Server.stopFileServerThread(neighbor);
                writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, message, iv, hmacDigest);
                break;
            case FAILED:
                if (isBadIntegrity)
                    return;
                message = concatenateContentBack(messageTokens, 4);
                neighbor = getNeighborByIpPort(ip, port);
                Platform.runLater(() -> Main.controller.showMessageBox("File Transfer - Corrupted File",
                        message, Alert.AlertType.INFORMATION));
                writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, message, iv, hmacDigest);
                break;
            case BYE:
                neighbor = getNeighborByIpPort(ip, port);
                Client.connectedNeighborsMap.remove(neighbor);
                if (!isBadIntegrity) {
                    Platform.runLater(() -> Main.controller.lvNeighbors.getItems().remove(ip + COLON + port + " - " + neighbor.getName()));
                    Platform.runLater(() -> Main.controller.tbChat.appendText(getCurrentDateTimeStamp() + space + neighbor.getName() + " left the conversation" + newLine));
                    writeToLog(Logger.LOG_LEVEL.INFO, "", neighbor, name, type, decryptedMessage.get(Security.SecurityToken.DECRYPTED_MESSAGE), iv, hmacDigest);
                }
                break;
            default:
                break;
        }
    }

    /**
     * A method to find a neighbor by ip and port
     * @param ip   - the ip of the neighbor
     * @param port - the port of the neighbor
     * @return - the requested neighbor if found, null otherwise
     */
    public static Configuration.Neighbor getNeighborByIpPort(String ip, String port) {
        for (Configuration.Neighbor neighbor : conf.getNeighbors()) {
            if (ip.equals(neighbor.getIp()) && port.equals(neighbor.getPort())) {
                return neighbor;
            }
        }
        return null;
    }

    /**
     * A method to concatenate salted message
     * @param array - the array contains the parts of the message
     * @param start - the index to start
     * @return concatenate message
     */
    public static String concatenateContentBack(String[] array, int start) {
        StringBuilder content = new StringBuilder();
        for (int i = start; i < array.length; i++) {
            content.append(" ").append(array[i]);
        }
        return content.toString();
    }

    /**
     * A method to add a name of a new connected client
     * @param ip   - the ip of the neighbor
     * @param port - the port of the neighbor
     * @param name - the name of the neighbor
     * @return neighbor instance
     */
    private Configuration.Neighbor addClientName(String ip, String port, String name) {
        Configuration.Neighbor neighbor = getNeighborByIpPort(ip, port);
        if (neighbor != null) {
            neighbor.setName(name);
        }
        return neighbor;
    }

    /**
     * A method to display and write in log bad integrity message
     * @param decryptedMessage - the decrypted message maps to tokens
     * @param iv               - the iv
     * @param hmacDigest       - the hmac digest
     */
    private void badIntegrityMessageDisplayLog(Map<Security.SecurityToken, String> decryptedMessage, String iv, String hmacDigest) {
        writeToLog(Logger.LOG_LEVEL.ERROR, "Integrity error, probably due to corrupted message or wrong mac key.",
                null, null, null,
                decryptedMessage.get(Security.SecurityToken.DECRYPTED_MESSAGE), iv, hmacDigest);
        Platform.runLater(() -> Main.controller.tbChat.appendText(getCurrentDateTimeStamp() + space + "Error: received a bad message - illegal or corrupted" + newLine));
    }

    /**
     * A method to generate random port
     * @return port
     */
    private int generatePort() {
        Random r = new Random();
        int low = 100;
        int high = 900;
        int result = r.nextInt(high - low) + low;
        return Integer.parseInt(conf.getPort()) + result;
    }
}
