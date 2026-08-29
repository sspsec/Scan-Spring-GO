# **SSP - Spring 框架漏洞扫描工具**

<img src="https://socialify.git.ci/sspsec/Scan-Spring-GO/image?description=1&descriptionEditable=%E9%92%88%E5%AF%B9SpringBoot%E7%9A%84%E6%B8%97%E9%80%8F%E5%B7%A5%E5%85%B7%EF%BC%8CSpringBoot%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%B7%A5%E5%85%B7&font=JetBrains%20Mono&forks=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F142762749%3Fv%3D4&name=1&owner=1&pattern=Matrix&stargazers=1&theme=Dark" alt="Scan-Spring-GO" width="640" height="320" />

## 🚀 简介

SSP 是一个使用 Go 语言实现的轻量、高效的 Spring 全家桶漏洞扫描与利用工具：支持 17 个漏洞模块的检测与利用、actuator/swagger/druid 信息泄露探测、自定义字典、并发限速控制，并内置 **MCP 服务端**——可将全部能力暴露给 AI 客户端（Claude Desktop、ZCode、Cursor 等），实现"AI 一句话完成从指纹识别到漏洞利用"的自动化渗透链路。

> 🤖 **本项目 v2.x 由 AI 全程重构**：架构重设计、17 个漏洞模块统一接口化、单元测试与 CI、MCP 服务端，全部由 AI（ZCode）完成，人工负责需求、验收与真实环境实测。

------

## 🛠️ 功能特性

- **多漏洞检测与利用**：17 个漏洞模块统一接口化（无害检测 `Detect` / 受控利用 `Exploit`），新增漏洞只需添加一个文件
- **信息泄露探测**：内置 210+ 端点字典（actuator/swagger/druid），支持 `-d` 合并、`-D` 替换自定义字典
- **双运行形态**：CLI 命令行 + MCP 服务端（stdio），检测与利用能力以结构化 JSON 输出
- **并发与限速**：worker pool + 全局限速 + 上下文取消，长时间运行状态稳定
- **安全闸门**：MCP 模式支持目标白名单（`--scope`）、利用工具独立开关（`--enable-exploit`）、全调用审计日志
- **彩色输出**：终端彩色文本 + 无色结果落盘，批量扫描互不干扰

------

## 🔥 支持的漏洞（17 个）

**RCE / SpEL 注入**

- **CVE-2022-22965** Spring Framework RCE（Spring4Shell）
- **CVE-2022-22963** Spring Cloud Function SpEL RCE
- **CVE-2022-22947** Spring Cloud Gateway SpEL RCE
- **CVE-2018-1273** Spring Data Commons SpEL RCE
- **CVE-2018-1270** Spring Messaging STOMP selector SpEL RCE
- **CVE-2017-8046** Spring Data REST PATCH 路径 SpEL RCE
- **CVE-2017-4971** Spring WebFlow transition 参数 SpEL RCE
- **CVE-2016-4977** Spring Security OAuth2 response_type SpEL RCE（回显型）

**信息泄露 / 文件读取**

- **CVE-2025-41243** Spring Cloud Gateway 环境属性修改（可扩展任意文件读取）
- **CVE-2025-41242** Spring Framework + Jetty URI 解析不一致路径穿越（Ghost Bits）
- **CVE-2021-21234** Spring Boot log view 任意文件读取
- **CVE-2022-22978** Spring Security RegexRequestMatcher 认证绕过

**反序列化 / 上传**

- **CVE-2024-37084** Spring Cloud Data Flow / Skipper 反序列化 RCE
- **SnakeYAML-RCE** Spring Boot 配置注入反序列化
- **Eureka-Xstream-RCE** Eureka XStream 反序列化
- **Jolokia-JNDI-RCE** Jolokia 配置不当导致 RCE
- **JeeSpring-2023** JeeSpringCloud 任意文件上传

------

## 📜 使用方法

### 🔍 漏洞检测（命中后可交互利用）

```bash
ssp -v http://example.com
```

<img width="1512" height="887" alt="image" src="https://github.com/user-attachments/assets/d2892c53-3311-4ce3-8e93-2d1e5b68e7e8" />


*自动完成指纹识别 + 全部漏洞的无害检测，命中后列出可利用模块，自主选择是否进入交互 shell。*

### 🧪 非交互命令执行

```bash
ssp -v http://example.com -c "id"                    # 首个命中且可利用的模块
ssp -v http://example.com -ce CVE-2022-22947 -c "id" # 指定漏洞模块执行
```

*脚本化/AI 调用推荐形态：探测 → 命中 → 执行 → 结构化结果。*

### 🔍 单 URL 信息泄露扫描

```bash
ssp -u http://example.com
```
<img width="1162" height="711" alt="image" src="https://github.com/user-attachments/assets/c9cdcfd4-93fc-4837-81ef-c1d2a98ecbf8" />


### 📄 批量扫描

```bash
ssp -uf urls.txt        # 批量信息泄露
ssp -vf urls.txt        # 批量漏洞检测
```

### 📚 自定义字典

```bash
ssp -u http://example.com -d mydict.txt   # 与内置字典合并（自动去重）
ssp -u http://example.com -D mydict.txt   # 完全替换内置字典
```

*字典每行一条路径，支持 `#` 注释，自动去 BOM、去重、清洗开头 `/`。*

### 🕹️ 代理 / 限速 / 并发

```bash
ssp -u http://example.com -p socks5://127.0.0.1:1080 -t 30 -delay 1 -timeout 5
```

------

## 🧑‍💻 命令行参数

| 参数 | 说明 |
| --- | --- |
| `-u <url>` | 对单个 URL 进行信息泄露扫描 |
| `-uf <file>` | 批量信息泄露扫描 |
| `-v <url>` | 对单个 URL 进行漏洞检测（命中后可交互利用） |
| `-vf <file>` | 批量漏洞检测 |
| `-c <cmd>` | 命中后执行单条命令（配合 `-v`，非交互） |
| `-ce <cve>` | 指定执行命令的漏洞 ID |
| `-p <proxy>` | 代理，格式 `socks5\|http://user:pass@host:port` |
| `-d <file>` | 自定义字典，与内置合并（`#` 为注释） |
| `-D <file>` | 自定义字典，完全替换内置 |
| `-t <n>` | 单目标端点探测并发数（默认 20） |
| `-o <file>` | 泄露扫描结果输出文件（默认 result.txt） |
| `-debug` | 输出每个失败请求的详情 |
| `-delay <s>` | 请求全局间隔（秒），0 为不限速 |
| `-timeout <s>` | 单请求超时（秒），默认 6 |
| `-version` | 输出版本号 |

------

## 🤖 MCP 模式（AI 调用）

将全部检测/利用能力暴露给 AI 客户端（Claude Desktop、ZCode、Cursor 等）：

```bash
ssp mcp --scope 127.0.0.1 --enable-exploit
```

### MCP 客户端配置示例

```json
{
  "mcpServers": {
    "scan-spring-go": {
      "command": "/path/to/ssp",
      "args": ["mcp", "--scope", "127.0.0.1", "--enable-exploit"]
    }
  }
}
```

### 工具清单

| 工具 | 说明 |
| --- | --- |
| `list_vulns` | 列出支持的漏洞模块（ID/类型/严重级别/参数说明） |
| `spring_fingerprint` | Spring 指纹识别 |
| `spring_leak_scan` | actuator/swagger/druid 信息泄露探测 |
| `spring_vuln_detect` | 全部（或指定 CVE 的）无害检测 |
| `spring_exploit` | 利用执行（**需 `--enable-exploit` 显式开启**） |
| `batch_scan` | 多目标批量检测 |

### 安全闸门

- `--scope`：目标白名单（域名/IP），出界请求直接拒绝
- `spring_exploit` 默认不注册，必须显式 `--enable-exploit` 启动
- 每次工具调用写 stderr 审计日志（时间/工具/目标/参数）

------

## 📦 构建

```bash
go build -o ssp .
go test ./...
```

------

## ⚠️ 注意事项

- 使用本工具进行漏洞扫描时，请务必遵守法律法规，仅在授权的范围内进行操作。
- 任何未经授权的系统扫描和利用行为可能触犯法律，用户应自行承担责任。
- 部分利用会修改目标运行时状态（如 CVE-2025-41243 的属性修改、CVE-2022-22965 的日志阀门），工具会在结束后尽力恢复，完整恢复建议重启目标服务。

------

## 📢 免责声明

本工具仅供技术研究和教育使用，请勿用于非法活动。若使用者因此产生任何法律责任，作者概不负责。

------

## ⭐ 最后

如果您觉得本工具有用，请为作者主页点个⭐，并关注公众号：**SSP安全研究**。

如果有任何问题或者希望添加新功能，请提交工单给我！我们会尽力改进工具，提供更多功能和支持。

![扫码关注公众号](https://github.com/sspsec/ssp/assets/142762749/0654010c-cdcc-4cf5-8f22-fc33b8d86642)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=sspsec/Scan-Spring-GO&type=Date)](https://star-history.com/#sspsec/Scan-Spring-GO&Date)
