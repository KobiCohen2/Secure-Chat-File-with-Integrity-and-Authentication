package com.kinneret.scaftia.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * A class represented a thread that listen to the client,
 * in order to release the ui main thread to interact with the user
 */
public class ServerListener extends Thread {

    private ServerSocket serverSocket;
    volatile boolean stop;

    ServerListener(ServerSocket serverSocket) {
        this.stop = false;
        this.serverSocket = serverSocket;
    }

    /**
     * A method that the thread will run when starts
     */
    @Override
    public void run() {
        try {
            while (!stop) {
                if (!stop && serverSocket != null && !serverSocket.isClosed()) {
                    Socket clientSocket = serverSocket.accept();
                    HandleClientThread hc = new HandleClientThread(clientSocket);
                    hc.start();
                    Server.connectedNeighbors.add(hc);
                }
            }
        }
        catch(Exception e) { e.printStackTrace(); }
        finally {
            try {
                if (serverSocket != null && !serverSocket.isClosed())
                    serverSocket.close();
            } catch (IOException e) { e.printStackTrace(); }
        }
    }
}
