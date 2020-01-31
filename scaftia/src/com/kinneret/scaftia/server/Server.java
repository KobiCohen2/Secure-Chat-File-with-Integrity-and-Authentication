package com.kinneret.scaftia.server;


import com.kinneret.scaftia.configuration.Configuration;
import com.kinneret.scaftia.ui.Controller;
import com.kinneret.scaftia.ui.Main;
import com.kinneret.scaftia.server.files.FileServerListener;
import javafx.application.Platform;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.*;

import static com.kinneret.scaftia.utils.CommonChars.COLON;

/**
 * A class represented Server
 */
public class Server {

    private static ServerSocket serverSocket;
    private static ServerListener listener;
    private static Map<Configuration.Neighbor, FileServerListener> fileServerListeners = Collections.synchronizedMap(new HashMap<>());
    static Set<HandleClientThread> connectedNeighbors = new HashSet<>();

    /**
     * An enum that contains message types
     */
    public enum MessageType {
        HELLO,
        MESSAGE,
        SENDFILE,
        OK,
        NO,
        BYE,
        ACK,
        FAILED,
        TOKEN,
        CHALLENGE,
        RESPONSE,
        FILE
    }

    /**
     * A method to start the server
     */
    public static void connect() {
        try {
            String ip = Controller.conf.getIp();
            int port = Integer.parseInt(Controller.conf.getPort());
            serverSocket = new ServerSocket(port, 10, InetAddress.getByName(ip));
            Platform.runLater(() -> {
                Main.controller.lblListening.setText("listening on " + ip + COLON + port);
                Main.controller.lblListening.setVisible(true);
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
        listener = new ServerListener(serverSocket);
        listener.start();
    }

    /**
     * A method to start file server thread
     * @param neighbor  - the sender
     * @param port - the port
     */
    public static void startFileServerThread(Configuration.Neighbor neighbor, int port)
    {
        try {
            String ip = Controller.conf.getIp();
            ServerSocket filesServerSocket = new ServerSocket(port, 10, InetAddress.getByName(ip));
            FileServerListener fileServerListener = new FileServerListener(filesServerSocket, neighbor);
            fileServerListener.start();
            fileServerListeners.put(neighbor, fileServerListener);
        }catch (Exception e){ e.printStackTrace(); }
    }

    /**
     * A method to stop file server thread
     * @param neighbor - the sender
     */
    public static void stopFileServerThread(Configuration.Neighbor neighbor)
    {
        try {
            FileServerListener listener = fileServerListeners.get(neighbor);
            //listener.getServerSocket().close();
            if(listener != null)
                listener.stop = true;
            fileServerListeners.remove(neighbor);
        } catch (Exception e) { e.printStackTrace(); }
    }

    /**
     * A method to stop the server
     */
    public static void disconnect() {
        connectedNeighbors.forEach(handleClientThread -> handleClientThread.stop = true);
        connectedNeighbors.clear();
        listener.stop = true;
        try {
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
