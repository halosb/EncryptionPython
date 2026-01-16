module com.example.encryptionpython {
    requires javafx.controls;
    requires javafx.fxml;

    // Commons Codec (automatic module name)
    requires org.apache.commons.codec;

    requires org.controlsfx.controls;
    requires org.kordamp.ikonli.javafx;
    requires org.kordamp.bootstrapfx.core;

    opens com.example.encryptionpython to javafx.fxml;
    exports com.example.encryptionpython;
}