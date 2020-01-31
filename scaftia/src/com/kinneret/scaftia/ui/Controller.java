package com.kinneret.scaftia.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.kinneret.scaftia.configuration.Configuration;
import com.kinneret.scaftia.client.Client;
import com.kinneret.scaftia.server.HandleClientThread;
import com.kinneret.scaftia.server.Server;
import com.kinneret.scaftia.utils.DateAndTime;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;

import static com.kinneret.scaftia.utils.CommonChars.newLine;
import static com.kinneret.scaftia.utils.CommonChars.space;
import static com.kinneret.scaftia.utils.DateAndTime.getCurrentDateTimeStamp;

public class Controller {

    public Button btnEdit;
    public Button btnSave;
    public Button btnLoad;
    public Button btnDisconnect;
    public Button btnConnect;
    public ListView lvNeighbors;
    public Button btnSend;
    public TextField tbSend;
    public TextArea tbChat;
    public Button btnSendFile;
    public TextField tbUserName;
    public static Configuration conf;
    public TextArea taConf;
    public Label lblListening;
    public RadioButton rbtWrongKeyFile;
    public RadioButton rbtWrongNumericalResponse;
    public RadioButton rbtWrongKeyResponse;
    public RadioButton rbtWrongKeyNonce;
    public RadioButton rbtRandomToken;
    public TextField tbTokenWrongUser;
    public TextField tbReceiverName;
    public TextField tbRequestorName;
    private File configurationFile;
    public static boolean isConnected = false;
    public static String userName;
    public static File selectedFile;

    /**
     * A method to start SCAFT
     */
    public void connect() {
        if (conf == null) {
            showMessageBox("Error", "You need to load configuration file before connecting", Alert.AlertType.ERROR);
            return;
        }
        if (conf.getMacPassword() == null || conf.getMacPassword().isEmpty()) {
            showMessageBox("Error", "HMAC-SHA256 key can not be empty", Alert.AlertType.ERROR);
            return;
        }
        if (tbUserName.getText().isEmpty()) {
            showMessageBox("Error", "You need to enter user name before connecting", Alert.AlertType.ERROR);
            return;
        }
        if (isConnected) {
            showMessageBox("Error", "You are already connected", Alert.AlertType.INFORMATION);
            return;
        }
        userName = tbUserName.getText();
        Server.connect();
        Client.connectClient();
    }

    /**
     * A method to stop SCAFT
     */
    public void disconnect() {
        if (!isConnected) {
            showMessageBox("Error", "You are already disconnected", Alert.AlertType.INFORMATION);
            return;
        }
        Client.sendToNeighbors(Server.MessageType.BYE, "");
        Server.disconnect();
        Client.disconnectClient();
        lblListening.setVisible(false);
        tbChat.appendText(getCurrentDateTimeStamp() + " You exited from the conversation" + newLine);
        lvNeighbors.getSelectionModel().clearSelection();
        lvNeighbors.getItems().clear();
        isConnected = false;
    }

    /**
     * A method to send message to all neighbors in the multi-cast
     */
    public void send() {
        String message = tbSend.getText().trim();
        if(!message.isEmpty())
        {
            Client.sendToNeighbors(Server.MessageType.MESSAGE, tbSend.getText());
            tbChat.appendText(DateAndTime.getCurrentDateTimeStamp() + space + userName + ": " + message + newLine);
            tbSend.clear();
        }
    }

    /**
     * A method to send file to specific neighbor in the multi-cast
     */
    public void sendFile()
    {
        Object obj = lvNeighbors.getSelectionModel().getSelectedItem();
        if(obj == null)
        {
            showMessageBox("Error", "Please select a neighbor first!", Alert.AlertType.ERROR);
            return;
        }
        String selectedNeighbor = (String) obj;
        selectedFile = openFileExplorerAndSelectFile("Choose a file to send");
        if(selectedFile == null)
        {
            showMessageBox("Error", "Please select a file!", Alert.AlertType.ERROR);
            return;
        }
        String[] tokens = selectedNeighbor.split("-");
        String ipPort = tokens[0].trim();
        String ip = ipPort.split(":")[0];
        String port = ipPort.split(":")[1];
        Configuration.Neighbor neighbor = HandleClientThread.getNeighborByIpPort(ip, port);
        Client.sendFileRequestToNeighbor(neighbor, selectedFile.getName());
    }

    /**
     * A method to open OS file explorer and select file
     * @param title - the title to set in the explorer window
     * @return the selected file
     */
    private File openFileExplorerAndSelectFile(String title) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        fileChooser.setTitle(title);
        return fileChooser.showOpenDialog(new Stage());
    }

    /**
     * A method to choose a directory in order to save a file
     * @param fileName - the name of the file
     * @return the saved file
     */
    public File chooseDirectory(String fileName)
    {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a directory to save the file");
        File defaultDirectory = new File(System.getProperty("user.home"));
        chooser.setInitialDirectory(defaultDirectory);
        chooser.setInitialFileName(fileName);
        return chooser.showSaveDialog(new Stage());
    }

    /**
     * A method to load a configuration file
     */
    public void loadConfigurationFile() {
        try {
            configurationFile = openFileExplorerAndSelectFile("Open Configuration File");
            if (configurationFile != null) {
                Gson gson = new Gson();
                conf = gson.fromJson(new FileReader(configurationFile), Configuration.class);
                taConf.setText(new String(Files.readAllBytes(configurationFile.toPath())));
                changeConfFieldsSate(false);
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    /**
     * A method to enable edit mode of the configuration file
     */
    public void editConfiguration() {
        changeConfFieldsSate(true);
    }

    /**
     * A method to save the configuration file
     */
    public void saveConfiguration() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        conf = gson.fromJson(taConf.getText(), Configuration.class);
        try (FileWriter writer = new FileWriter(configurationFile)) {
            gson.toJson(conf, writer);
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        changeConfFieldsSate(false);
    }

    /**
     * A method to set edit mode of the configuration file text area
     * @param isEditable - boolean to set the mode
     */
    private void changeConfFieldsSate(boolean isEditable) {
        taConf.setEditable(isEditable);
    }

    /**
     * A method to show message box to user
     * @param title - the title of the message box
     * @param message - the content of the message
     * @param type - the type of the message box
     * @param buttons - the buttons of the message box (optional)
     * @return the instance of the message box
     */
    public Alert showMessageBox(String title, String message, Alert.AlertType type, ButtonType...buttons) {
        Alert alert = new Alert(type, "", buttons);
        alert.setTitle(title);
        //alert.setHeaderText("Information Alert");
        alert.setContentText(message);
        if(buttons.length == 0)
        {
            alert.show();
            return null;
        } else {
            return alert;
        }
    }
}
