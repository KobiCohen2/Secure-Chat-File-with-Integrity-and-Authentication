package com.kinneret.scaftia.auth.server.configuration;

import java.util.List;
import java.util.Map;

/**
 * A class represent data model of a configuration file
 */
public class Configuration {

    private String ip;
    private String port;
    private String spPassword;
    private String macPassword;
    private Map<String, User> users;

    /**
     * Constructor
     * @param ip - ip the server listening on
     * @param port - port the server listening on
     * @param users - list of users
     */
    public Configuration(String ip, String port, Map<String, User> users) {
        this.ip = ip;
        this.port = port;
        this.users = users;
    }

    /*** Setters ***/
    public void setIp(String ip) { this.ip = ip; }

    public void setPort(String port) { this.port = port; }

    public void setUsers(Map<String, User> users) { this.users = users; }

    public void setSpPassword(String spPassword) { this.spPassword = spPassword; }

    public void setMacPassword(String macPassword) { this.macPassword = macPassword; }

    /*** Getters ***/
    public String getIp() { return ip; }

    public String getPort() { return port; }

    public Map<String, User> getUsers() { return users; }

    public String getSpPassword() { return spPassword; }

    public String getMacPassword() { return macPassword; }

    /**
     * An inner class, represent data model of user
     */
    public static class User
    {
        private String name;
        private String ip;
        private String port;
        private String password;

        /**
         * Constructor
         * @param name - the name of the user
         * @param ip - the ip of the user
         * @param port - the port of the user
         * @param password - the personal password of the user
         */
        public User(String name, String ip, String port, String password) {
            this.name = name;
            this.ip = ip;
            this.port = port;
            this.password = password;
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

        public void setPassword(String password) { this.password = password; }

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

        public String getPassword() { return password; }

    }
}