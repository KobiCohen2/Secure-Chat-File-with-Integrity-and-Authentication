package com.kinneret.scaftia.auth.server;

import java.net.ServerSocket;
import java.net.Socket;

/**
 * A class represented a thread that listen to the client,
 * in order to release the ui main thread to interact with the user
 */
public class ServerListener extends Thread {

    private ServerSocket serverSocket;
    public boolean stop;

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
                }
            }
        }
        catch(Exception e) { e.printStackTrace(); }
        finally {
            try {
                serverSocket.close();
            } catch (Exception e) { e.printStackTrace(); }
        }
    }
}
