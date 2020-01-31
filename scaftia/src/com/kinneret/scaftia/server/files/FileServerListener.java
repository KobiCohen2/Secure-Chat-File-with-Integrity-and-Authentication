package com.kinneret.scaftia.server.files;

import com.kinneret.scaftia.configuration.Configuration;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * A class represent a listener of incoming connections for file transfer
 */
public class FileServerListener extends Thread {

    private ServerSocket serverSocket;
    public volatile boolean stop;
    private Configuration.Neighbor neighbor;

    public FileServerListener(ServerSocket serverSocket, Configuration.Neighbor neighbor) {
        this.stop = false;
        this.serverSocket = serverSocket;
        this.neighbor = neighbor;
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
                    HandleFileTransferThread fileTransferThread = new HandleFileTransferThread(clientSocket, neighbor);
                    fileTransferThread.start();
                }
            }
        }
        catch(Exception e) { e.printStackTrace(); }
        finally {
            try {
                if (serverSocket != null && !serverSocket.isClosed())
                    serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
