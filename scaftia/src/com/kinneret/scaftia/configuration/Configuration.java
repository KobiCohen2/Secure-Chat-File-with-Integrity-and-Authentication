package com.kinneret.scaftia.configuration;

import java.util.List;

/**
 * A class represent data model of a configuration file
 */
public class Configuration {

    private String password;
    private String macPassword;
    private String authPassword;
    private String authServerIp;
    private String authServerPort;
    private String ip;
    private String port;
    private List<Neighbor> neighbors;

    /**
     * Constructor
     * @param password - public key
     * @param macPassword - MAC key
     * @param neighbors - list of neighbors
     */
    public Configuration(String password, String macPassword, List<Neighbor> neighbors) {
        this.password = password;
        this.macPassword = macPassword;
        this.neighbors = neighbors;
    }

    /*** Setters ***/
    public void setPassword(String password) {
        this.password = password;
    }

    public void setMacPassword(String macPassword) { this.macPassword = macPassword; }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public void setNeighbors(List<Neighbor> neighbors) {
        this.neighbors = neighbors;
    }

    public void setAuthPassword(String authPassword) { this.authPassword = authPassword; }

    public void setAuthServerIp(String authServerIp) { this.authServerIp = authServerIp; }

    public void setAuthServerPort(String authServerPort) { this.authServerPort = authServerPort; }

    /*** Getters ***/
    public String getPassword() {
        return password;
    }

    public String getMacPassword() { return macPassword; }

    public String getIp() {
        return ip;
    }

    public String getPort() {
        return port;
    }

    public List<Neighbor> getNeighbors() {
        return neighbors;
    }

    public String getAuthPassword() { return authPassword; }

    public String getAuthServerIp() { return authServerIp; }

    public String getAuthServerPort() { return authServerPort; }

    public Neighbor getNeighborByName(String name)
    {
        for (Neighbor neighbor : this.getNeighbors()) {
            if (name.equalsIgnoreCase(neighbor.getName())) {
                return neighbor;
            }
        }
        return null;
    }

    /**
     * An inner class, represent data model of neighbor
     */
    public static class Neighbor
    {
        private String name;
        private String ip;
        private String port;

        /**
         * Constructor
         * @param name - the name of the neighbor
         * @param ip - the ip of the neighbor
         * @param port - the port of the neighbor
         */
        public Neighbor(String name, String ip, String port) {
            this.name = name;
            this.ip = ip;
            this.port = port;
        }

        /*** Setters ***/
        public void setName(String name) {
            this.name = name;
        }

        public void setIp(String ip) {
            this.ip = ip;
        }

        public void setPort(String port) {
            this.port = port;
        }

        /*** Getters ***/
        public String getName() {
            return name;
        }

        public String getIp() {
            return ip;
        }

        public String getPort() {
            return port;
        }
    }
}