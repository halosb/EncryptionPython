# 打包为可运行 JAR 与 Windows 单文件 EXE

1. 生成可运行 JAR（包含依赖）：

```bash
mvn package
```

生成的 JAR 在 `target` 目录下（如使用 shade 插件会生成包含依赖的可运行 JAR）。

2. 生成 Windows EXE（示例，使用 `jpackage`）：

- 确认已安装 JDK 17 带 `jpackage` 的发行版。
- 打包示例命令：

```bash
jpackage --input target --name EncryptionPython --main-jar EncryptionPython-1.0-SNAPSHOT.jar --main-class com.example.encryptionpython.Launcher --type exe
```

（请根据本地环境调整参数）
