package com.example.encryptionpython;

import com.example.encryptionpython.core.CryptoUtils;
import com.example.encryptionpython.core.Obfuscator;
import com.example.encryptionpython.core.PythonPacker;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.time.LocalDate;

public class MainController {
    @FXML private TextField inputFileField;
    @FXML private TextField outputDirField;

    @FXML private PasswordField passwordField;
    @FXML private PasswordField confirmPasswordField;
    @FXML private TextField lockThresholdField;
    @FXML private TextField lockMinutesField;

    @FXML private DatePicker expiryDatePicker;
    @FXML private CheckBox enableExpiryCheck;

    @FXML private CheckBox bindCpu;
    @FXML private CheckBox bindDisk;
    @FXML private CheckBox bindMac;
    @FXML private CheckBox bindCwd;
    @FXML private Button selectAllBind;

    @FXML private TextArea logArea;

    @FXML private Button chooseFileBtn;
    @FXML private Button chooseOutputBtn;
    @FXML private Button startBtn;

    private Stage primaryStage;

    public void setStage(Stage stage) {
        this.primaryStage = stage;
    }

    @FXML
    public void initialize() {
        // defaults
        lockThresholdField.setText("5");
        lockMinutesField.setText("10");
        expiryDatePicker.setValue(LocalDate.now().plusDays(30));
        enableExpiryCheck.setSelected(false);
        selectAllBind.setOnAction(e -> toggleAllBindings());
        log("界面已初始化");
    }

    private void toggleAllBindings() {
        boolean any = !(bindCpu.isSelected() && bindDisk.isSelected() && bindMac.isSelected() && bindCwd.isSelected());
        bindCpu.setSelected(any);
        bindDisk.setSelected(any);
        bindMac.setSelected(any);
        bindCwd.setSelected(any);
    }

    @FXML
    private void onChooseFile() {
        FileChooser chooser = new FileChooser();
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Python Files", "*.py"));
        File f = chooser.showOpenDialog(primaryStage);
        if (f != null) {
            inputFileField.setText(f.getAbsolutePath());
            log("选择文件: " + f.getAbsolutePath());
        }
    }

    @FXML
    private void onChooseOutput() {
        DirectoryChooser chooser = new DirectoryChooser();
        File d = chooser.showDialog(primaryStage);
        if (d != null) {
            outputDirField.setText(d.getAbsolutePath());
            log("输出目录: " + d.getAbsolutePath());
        }
    }

    @FXML
    private void onStartEncrypt() {
        String in = inputFileField.getText();
        String outDir = outputDirField.getText();
        String pwd = passwordField.getText();
        String pwd2 = confirmPasswordField.getText();
        if (in == null || in.isEmpty()) { log("请选择要加密的 Python 文件"); return; }
        if (outDir == null || outDir.isEmpty()) { log("请选择输出目录"); return; }
        if (pwd == null || pwd.isEmpty()) { log("请输入密码"); return; }
        if (!pwd.equals(pwd2)) { log("两次密码输入不一致"); return; }

        int threshold = Integer.parseInt(lockThresholdField.getText());
        int lockMins = Integer.parseInt(lockMinutesField.getText());

        boolean useExpiry = enableExpiryCheck.isSelected();
        final String expiryVal = useExpiry && expiryDatePicker.getValue() != null ? expiryDatePicker.getValue().toString() : null;

        boolean[] binds = new boolean[]{bindCpu.isSelected(), bindDisk.isSelected(), bindMac.isSelected(), bindCwd.isSelected()};

        log("开始加密...");
        startBtn.setDisable(true);

        // perform encryption on background thread
        new Thread(() -> {
            try {
                // obfuscate password and generate salt/hash
                byte[] salt = CryptoUtils.generateSalt(16);
                String obf = CryptoUtils.obfuscatePassword(pwd);
                String hash = CryptoUtils.sha256Hex(salt, obf);

                File inFile = new File(in);
                File outFile = PythonPacker.pack(inFile, new File(outDir), salt, hash, obf, threshold, lockMins, useExpiry, expiryVal, binds);
                log("加密完成: " + outFile.getAbsolutePath());
            } catch (Exception ex) {
                log("加密失败: " + ex.getMessage());
                ex.printStackTrace();
            } finally {
                Platform.runLater(() -> startBtn.setDisable(false));
            }
        }).start();
    }

    @FXML
    private void onClearConfig() {
        inputFileField.clear(); outputDirField.clear(); passwordField.clear(); confirmPasswordField.clear();
        lockThresholdField.setText("5"); lockMinutesField.setText("10"); enableExpiryCheck.setSelected(false);
        bindCpu.setSelected(false); bindDisk.setSelected(false); bindMac.setSelected(false); bindCwd.setSelected(false);
        log("配置已清空");
    }

    @FXML
    private void onHelp() {
        String help = "使用说明:\n1) 选择 .py 文件并设置输出目录。\n2) 输入密码并配置绑定/到期等参数。\n3) 点击开始加密，生成受保护的 Python 文件。";
        log(help);
        Alert a = new Alert(Alert.AlertType.INFORMATION, help, ButtonType.OK);
        a.setHeaderText("帮助"); a.showAndWait();
    }

    private void log(String s) {
        Platform.runLater(() -> {
            logArea.appendText(s + "\n");
        });
    }
}
