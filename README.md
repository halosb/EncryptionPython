# Python 加密保护工具（Java + JavaFX + Maven）

快速说明：本工具用 JavaFX 提供可视化界面，对 Python 脚本生成带有运行时验证（密码、到期、绑定、反调试、完整性校验等）的保护脚本，生成的脚本不依赖第三方库，兼容 Python 3.6+。

构建与运行：

1. 使用 JDK 17 构建：

```bash
mvn package
```

2. 运行（开发模式）：

```bash
mvn javafx:run
```

3. 输出：`target` 下会生成可运行的 JAR；参见 `PACKAGING.md` 了解如何生成 Windows EXE。

测试：使用 `demo.py` 作为测试脚本执行加密流程。
