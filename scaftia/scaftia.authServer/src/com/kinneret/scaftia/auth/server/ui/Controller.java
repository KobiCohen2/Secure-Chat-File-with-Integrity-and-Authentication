package com.kinneret.scaftia.auth.server.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.kinneret.scaftia.auth.server.Server;
import com.kinneret.scaftia.auth.server.configuration.Configuration;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ResourceBundle;


public class Controller implements Initializable {

    public Button btnDisconnect;
    public Button btnConnect;
    public static Configuration conf;
    public TextArea taConf;
    public Label lblListening;
    public ToggleButton toggleEdit;
    public TextArea tbResponses;
    public TextArea tbRequests;
    public RadioButton rbtnWrongRecipientKey;
    public RadioButton rbtnWrongRequestorKey;
    public TextField taInvalidTargetName;
    public RadioButton rbtnInvalidNonce;
    private File configurationFile;
    public static boolean isConnected = false;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        //load configuration file automatically
        configurationFile = new File("SCAFTIA-Server-Conf.json");
        loadConfigurationFile();
        //configuration text area listener in order to save changes automatically
        taConf.textProperty().addListener((observable, oldValue, newValue) -> saveConfiguration());
    }

    /**
     * A method to start SCAFT
     */
    public void connect() {
        if (isConnected)
        {
            showMessageBox("SCAFTIA", "You are already connected!", Alert.AlertType.INFORMATION);
            return;
        }
        Server.connect();
        isConnected = true;
    }

    /**
     * A method to stop SCAFT
     */
    public void disconnect() {
        if (!isConnected)
        {
            showMessageBox("SCAFTIA", "You are not connected!", Alert.AlertType.INFORMATION);
            return;
        }
        Server.disconnect();
        lblListening.setVisible(false);
        isConnected = false;
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
     * A method to load a configuration file
     */
    public void loadConfigurationFile() {
        try {
            configurationFile = configurationFile == null ? openFileExplorerAndSelectFile("Open Configuration File") : configurationFile;
            if (configurationFile != null) {
                Gson gson = new Gson();
                conf = gson.fromJson(new FileReader(configurationFile), Configuration.class);
                taConf.setText(new String(Files.readAllBytes(configurationFile.toPath())));
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void editToggle()
    {
        changeConfFieldsSate(toggleEdit.isSelected());
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
