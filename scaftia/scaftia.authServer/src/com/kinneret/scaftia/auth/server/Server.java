package com.kinneret.scaftia.auth.server;

import com.kinneret.scaftia.auth.server.ui.Controller;
import com.kinneret.scaftia.auth.server.ui.Main;
import javafx.application.Platform;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;

import static com.kinneret.scaftia.auth.server.utils.CommonChars.COLON;

/**
 * A class represented Server
 */
public class Server {

    private static ServerSocket serverSocket;
    private static ServerListener listener;

    /**
     * A method to start the server
     */
    public static void connect() {
        try {
            String ip = Controller.conf.getIp();
            int port = Integer.parseInt(Controller.conf.getPort());
            serverSocket = new ServerSocket(port, 10, InetAddress.getByName(ip));
            listener = new ServerListener(serverSocket);
            listener.start();
            Platform.runLater(() -> {
                Main.controller.lblListening.setText("Server is on - listening on " + ip + COLON + port);
                Main.controller.lblListening.setVisible(true);
            });
        }catch (Exception e) { e.printStackTrace(); }
    }

    /**
     * A method to stop the server
     */
    public static void disconnect() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        listener.stop = true;
    }
}
