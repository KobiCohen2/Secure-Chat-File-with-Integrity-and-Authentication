package com.kinneret.scaftia.auth.server;

import com.kinneret.scaftia.auth.server.security.Security;
import com.kinneret.scaftia.auth.server.ui.Main;
import com.kinneret.scaftia.auth.server.utils.ByteManipulation;
import com.kinneret.scaftia.auth.server.utils.Logger;
import javafx.application.Platform;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.UUID;

import static com.kinneret.scaftia.auth.server.security.Security.*;
import static com.kinneret.scaftia.auth.server.ui.Controller.conf;
import static com.kinneret.scaftia.auth.server.utils.CommonChars.newLine;
import static com.kinneret.scaftia.auth.server.utils.CommonChars.space;
import static com.kinneret.scaftia.auth.server.utils.DateAndTime.getCurrentDateTimeStamp;
import static com.kinneret.scaftia.auth.server.utils.Logger.writeToLog;

/**
 * A class represented a thread that listen to the client messages
 */
public class HandleClientThread extends Thread {

    private Socket clientSocket;
    boolean stop = false;

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
     * @param message - message to process
     */
    private void processMessage(String message) {
        String[] tokens = message.split(space);
        String sender = "", recipient = "", nonce = "", digest = "";
        try {
            sender = tokens[0];
            recipient = tokens[1];
            nonce = tokens[2];
            digest = tokens[3];
        } catch (Exception e) { e.printStackTrace(); }
        String returnedMessage;

        boolean isHmacValid = checkDigest(sender + space + recipient + space + nonce, digest);
        String errorMessage = "";
        String result = "";

        if(!isHmacValid)
        {
            errorMessage = "Invalid integrity - hmac test failed";
            returnedMessage = encryptMessage(errorMessage, conf.getSpPassword());
            writeToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, conf.getUsers().get(recipient), "an error occurred, sent error message",
                    nonce, false, isHmacValid, false, "no, an error occurred");
            result = errorMessage + newLine + "send back an error message.";
        } else {
            if (!conf.getUsers().containsKey(sender)) {
                errorMessage = "Invalid sender name (" + sender + ") - does not exists in server's database";
                returnedMessage = encryptMessage(errorMessage, conf.getSpPassword());
                writeToLog(Logger.LOG_LEVEL.ERROR, errorMessage, null, conf.getUsers().get(recipient), "an error occurred, sent error message",
                        nonce, false, isHmacValid, false, "no, an error occurred");
                result = errorMessage + newLine + "send back an error message.";
            } else if (!conf.getUsers().containsKey(recipient)) {
                errorMessage = "Invalid recipient name (" + recipient + ") - does not exists in server's database";
                returnedMessage = encryptMessage(errorMessage, conf.getSpPassword());
                writeToLog(Logger.LOG_LEVEL.ERROR, errorMessage, conf.getUsers().get(sender), null, "an error occurred, sent error message",
                        nonce, false, isHmacValid, false, "no, an error occurred");
                result = errorMessage + newLine + "send back an error message.";
            } else {
                boolean invalidNonce = Main.controller.rbtnInvalidNonce.isSelected();
                boolean wrongRequestorKey = Main.controller.rbtnWrongRequestorKey.isSelected();
                boolean wrongRecipientKey = Main.controller.rbtnWrongRecipientKey.isSelected();
                boolean invalidTargetName = Main.controller.taInvalidTargetName.getText().isEmpty();
                nonce = invalidNonce ? ByteManipulation.bytesToHex(Security.generateRandomBytes(IV_NONCE_SIZE)) : nonce;
                String requestorKey = wrongRequestorKey ? UUID.randomUUID().toString() : conf.getUsers().get(sender).getPassword();
                String recipientKey = wrongRecipientKey ? UUID.randomUUID().toString() : conf.getUsers().get(recipient).getPassword();
                recipient = invalidTargetName ? recipient : Main.controller.taInvalidTargetName.getText();
                returnedMessage = generateMessage(sender, recipient, nonce, requestorKey, recipientKey);
                String send = "Send new auth response - sender: " + sender + ", recipient: " + recipient;
                if (invalidNonce) {
                    result = "Invalid nonce attack" + newLine + send;
                    writeToLog(Logger.LOG_LEVEL.INFO, "no error occurred", conf.getUsers().get(sender), conf.getUsers().get(recipient),
                            send, nonce, false, isHmacValid, true, "yes, invalid nonce attack");
                } else if (wrongRequestorKey) {
                    result = "Wrong requestor key attack" + newLine + send;
                    writeToLog(Logger.LOG_LEVEL.INFO, "no error occurred", conf.getUsers().get(sender), conf.getUsers().get(recipient),
                            send, nonce, false, isHmacValid, true, "yes, wrong requestor key attack");
                } else if (wrongRecipientKey) {
                    result = "Wrong recipient key attack" + newLine + send;
                    writeToLog(Logger.LOG_LEVEL.INFO, "no error occurred", conf.getUsers().get(sender), conf.getUsers().get(recipient),
                            send, nonce, false, isHmacValid, true, "yes, wrong recipient attack");
                } else if (!invalidTargetName) {
                    result = "Invalid target name attack" + newLine + send;
                    writeToLog(Logger.LOG_LEVEL.INFO, "no error occurred", conf.getUsers().get(sender), conf.getUsers().get(recipient),
                            send, nonce, false, isHmacValid, true, "yes, invalid target name attack");
                } else {
                    result = "Correct response" + newLine + send;
                    writeToLog(Logger.LOG_LEVEL.INFO, "no error occurred", conf.getUsers().get(sender), conf.getUsers().get(recipient),
                            send, nonce, false, isHmacValid, true, "no, correct response");
                }
            }
        }

        String finalRecipient = recipient;
        String finalSender = sender;
        String finalResult = result;
        Platform.runLater(() -> {
            Main.controller.tbRequests.appendText(getCurrentDateTimeStamp() + newLine +
                    "Received new auth request - sender: " + finalSender + ", recipient: " + finalRecipient + newLine +
                    "----------------------------------------------------------------------------" + newLine);
            Main.controller.tbResponses.appendText(getCurrentDateTimeStamp() + newLine +
                    finalResult + newLine +
                    "----------------------------------------------------------------------------" + newLine);
        });

        try {
            PrintWriter pw = new PrintWriter(clientSocket.getOutputStream());
            pw.write(returnedMessage + newLine);
            pw.flush();
            this.stop = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
