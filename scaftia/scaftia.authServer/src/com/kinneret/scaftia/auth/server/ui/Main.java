package com.kinneret.scaftia.auth.server.ui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

public class Main extends Application {

    public static Controller controller;

    @Override
    public void start(Stage primaryStage) throws Exception{
        FXMLLoader fxmlLoader = new FXMLLoader();
        Pane pane = fxmlLoader.load(getClass().getResource("SCAFTIA-AuthServer.fxml").openStream());
        controller = fxmlLoader.getController();
        primaryStage.setTitle("SCAFTIA-AuthServer");
        primaryStage.setScene(new Scene(pane, 1200, 730));
        primaryStage.setResizable(false);
        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
