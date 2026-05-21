# 📖 JSLeakHunter 使用说明与部署文档

---

## 📋 目录

1. [项目简介](#项目简介)
2. [功能特性](#功能特性)
3. [系统要求](#系统要求)
4. [快速部署](#快速部署)
5. [使用说明](#使用说明)
6. [配置说明](#配置说明)
7. [目录结构](#目录结构)
8. [常见问题](#常见问题)
9. [更新日志](#更新日志)

---

## 🎯 项目简介

**JSLeakHunter** 是一款AI驱动的前端JS文件硬编码泄露检测工具，用于自动化扫描和分析JavaScript文件中的敏感信息泄露，包括API密钥、数据库连接字符串、内部配置等安全风险。

**版本**: v2.0
**作者**: Security Team
**协议**: MIT License

---

## ✨ 功能特性

| 功能模块         | 说明                                          |
| ---------------- | --------------------------------------------- |
| 🔍 **JS文件提取** | 自动提取目标网站的所有JS文件，支持SPA单页应用 |
| 🤖 **AI智能分析** | 接入大模型API进行深度语义分析                 |
| 📝 **正则预检**   | 内置100+敏感信息正则匹配规则                  |
| 🎯 **选择性扫描** | 支持勾选特定JS文件进行定向扫描                |
| 📊 **报告导出**   | 支持JSON、CSV、Markdown三种格式导出           |
| 📡 **实时日志**   | SSE推送扫描进度和实时日志                     |
| 📜 **历史记录**   | 保存扫描历史，支持查看和批量删除              |
| 🔐 **多级风险**   | HIGH/MEDIUM/LOW 三级风险分类                  |

---

## 💻 系统要求

### 必需环境

| 项目     | 最低版本               | 推荐版本                |
| -------- | ---------------------- | ----------------------- |
| Python   | 3.8+                   | 3.10+                   |
| pip      | 20.0+                  | 最新版                  |
| 操作系统 | Windows 10/Linux/macOS | Windows 11/Ubuntu 22.04 |
| 内存     | 2GB                    | 4GB+                    |
| 磁盘空间 | 500MB                  | 1GB+                    |

### 可选环境

| 项目               | 说明                     |
| ------------------ | ------------------------ |
| Chrome浏览器       | 用于渲染SPA页面（可选）  |
| Selenium WebDriver | 深度爬取动态页面（可选） |
| AI API密钥         | 启用AI分析功能（可选）   |

---

## 🚀 快速部署

### 方式一：本地部署（推荐）

#### 第1步：下载项目

```bash
# 克隆项目
git clone https://github.com/your-repo/jsleakhunter.git
cd jsleakhunter

# 或直接下载解压
```

#### 第2步：创建虚拟环境

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

#### 第3步：安装依赖

```bash
pip install -r requirements.txt
```

**requirements.txt 内容**：

```txt
flask>=2.3.0
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
urllib3>=2.0.0
```

#### 第4步：启动服务

```bash
# Windows (推荐使用start.bat)
start.bat

# 或直接运行
python app.py

# Linux/macOS
python3 app.py
```

#### 第5步：访问界面

打开浏览器访问：**http://127.0.0.1:5000**

---

---

### 方式二：Windows一键部署

创建 `start.bat` 文件：

```bat
@echo off
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

echo [+] Activating virtual environment...
call venv\Scripts\activate.bat

echo [+] Starting JSLeakHunter...
python app.py

pause
```

双击 `start.bat` 即可启动。

---

## 📖 使用说明

### 一、基础扫描流程

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  输入目标URL  │ ->│  提取JS文件   │ -> │  选择文件    │ -> │  开始扫描    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

#### 步骤1：输入目标URL

在首页输入框中输入目标网站地址：

```
https://www.example.com
```

支持格式：

- `https://www.example.com`
- `http://www.example.com`
- `www.example.com`（自动添加https）
- `example.com`（自动补全）

#### 步骤2：提取JS文件

点击 **「提取JS文件」** 按钮，系统将：

1. 访问目标页面
2. 解析HTML中的所有 `<script>` 标签
3. 列出所有可扫描的JS文件

#### 步骤3：选择扫描文件

在文件列表中勾选要扫描的JS文件：

- ✅ 勾选单个文件
- ✅ 全选/取消全选
- 查看文件大小和类型

#### 步骤4：开始扫描

点击 **「开始扫描」** 按钮，系统将：

1. 下载JS文件内容
2. 正则预检敏感信息
3. AI深度分析（如配置API）
4. 生成扫描结果

---

### 二、查看扫描结果

扫描完成后，结果页面显示：

| 字段         | 说明                                    |
| ------------ | --------------------------------------- |
| **风险等级** | 🔴 HIGH / 🟡 MEDIUM / 🟢 LOW               |
| **问题类型** | API_KEY / DB_PASSWORD / INTERNAL_URL 等 |
| **文件位置** | 发现问题的JS文件URL                     |
| **行号**     | 问题所在的代码行                        |
| **证据**     | 匹配到的敏感内容                        |
| **来源**     | regex（正则）/ ai（AI分析）             |
| **修复建议** | 针对该问题的修复方案                    |

---

### 三、导出报告

支持三种格式导出：

#### JSON格式

```bash
GET /api/scan/{scan_id}/export/json
```

#### CSV格式

```bash
GET /api/scan/{scan_id}/export/csv
```

#### Markdown格式

```bash
GET /api/scan/{scan_id}/export/markdown
```

---

### 四、查看历史记录

访问 **「历史记录」** 页面：

- 查看所有扫描历史
- 按时间排序
- 筛选不同状态
- 批量删除记录

---

## ⚙️ 配置说明

### 基础配置

在扫描界面可配置以下参数：

| 参数         | 说明               | 默认值 |
| ------------ | ------------------ | ------ |
| **目标URL**  | 要扫描的网站地址   | 必填   |
| **Cookie**   | 访问需要登录的页面 | 空     |
| **爬取深度** | 递归爬取深度       | 2      |

### AI配置（可选）

| 参数         | 说明          | 示例                        |
| ------------ | ------------- | --------------------------- |
| **API地址**  | 大模型API端点 | `https://api.openai.com/v1` |
| **API密钥**  | 认证密钥      | `sk-xxxxx`                  |
| **模型名称** | 使用的模型    | `gpt-4` / `mimo-v2.5-pro`   |

### 支持的AI模型

| 模型         | API地址                                   | 说明     |
| ------------ | ----------------------------------------- | -------- |
| OpenAI GPT-4 | `https://api.openai.com/v1`               | 效果最佳 |
| 小米MiMo     | `https://token-plan-cn.xiaomimimo.com/v1` | 国内可用 |
| 通义千问     | `https://dashscope.aliyuncs.com/api/v1`   | 阿里云   |
| 本地模型     | `http://localhost:11434/v1`               | Ollama   |

---

## 📁 目录结构

```
jsleakhunter/
├── app.py                  # Flask主程序
├── scanner.py              # 扫描引擎
├── analyzer.py             # AI分析器
├── js_extractor.py         # JS文件提取器
├── patterns.py             # 正则规则库
├── requirements.txt        # Python依赖
├── start.bat               # Windows启动脚本
├── README.md               # 项目说明
│
├── data/                   # 数据目录
│   └── scans.db           # SQLite数据库
│
├── static/                 # 静态资源
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── app.js
│   └── img/
│
└── templates/              # HTML模板
    └── index.html
```

---

## ❓ 常见问题

### Q1: 启动时报错 `UnicodeEncodeError`

**解决方案**：

```bash
# 方法1：设置环境变量
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
python app.py

# 方法2：使用start.bat启动
start.bat
```

---

### Q2: 无法访问目标网站

**可能原因**：

- 目标网站有WAF防护
- 需要登录Cookie
- 网络连接问题

**解决方案**：

1. 配置有效的Cookie
2. 检查网络连接
3. 降低爬取深度

---

### Q3: AI分析不生效

**检查项**：

- [ ] API密钥是否正确
- [ ] API地址是否可达
- [ ] 模型名称是否正确
- [ ] 网络是否通畅

**测试连接**：

```bash
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}'
```

---

### Q4: 扫描速度慢

**优化建议**：

1. 减少选择的JS文件数量
2. 关闭AI分析（不填API密钥）
3. 降低爬取深度为1
4. 只扫描关键业务JS文件

---

### Q5: 数据库锁定错误

**解决方案**：

```bash
# 删除数据库文件重新创建
rm data/scans.db
python app.py
```

---

### Q6: 端口被占用

**修改端口**：

编辑 `app.py` 最后一行：

```python
# 修改前
app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

# 修改后（使用8080端口）
app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
```

---

## 📝 使用示例

### 示例1：扫描单个网站

```
目标URL: https://www.example.com
Cookie: (留空)
爬取深度: 2
AI配置: (不填，使用纯正则)
```

**预期结果**：

- 发现 5-10 个可疑模式
- 耗时 30-60 秒

---

### 示例2：扫描需要登录的后台

```
目标URL: https://admin.example.com
Cookie: session=abc123; token=xyz789
爬取深度: 1
API密钥: sk-xxxxx
模型: gpt-4
```

**预期结果**：

- AI发现更多语义化问题
- 耗时 2-5 分钟

---

### 示例3：批量扫描多个域名

在目标URL中用逗号分隔：

```
https://site1.com,https://site2.com,https://site3.com
```

---

## 🔧 API接口文档

### 1. 提取JS文件

```http
POST /api/extract
Content-Type: application/json

{
  "target": "https://example.com",
  "cookie": "",
  "depth": 2
}
```

**响应**：

```json
{
  "success": true,
  "target": "https://example.com",
  "total": 15,
  "js_files": [...],
  "stats": {...}
}
```

---

### 2. 扫描选中文件

```http
POST /api/scan-selected
Content-Type: application/json

{
  "js_urls": ["https://example.com/app.js"],
  "api_key": "",
  "api_url": "",
  "model": "gpt-4"
}
```

**响应**：

```json
{
  "scan_id": "abc12345",
  "total_files": 1
}
```

---

### 3. 获取扫描结果

```http
GET /api/scan/{scan_id}/results
```

---

### 4. 实时事件流

```http
GET /api/scan/{scan_id}/events
```

返回SSE事件流：

```
data: {"type": "log", "message": "[*] Scanning..."}
data: {"type": "progress", "value": 50}
data: {"type": "done"}
```

---

### 5. 导出报告

```http
GET /api/scan/{scan_id}/export/json
GET /api/scan/{scan_id}/export/csv
GET /api/scan/{scan_id}/export/markdown
```

---

### 6. 历史记录

```http
GET /api/history
```

---

### 7. 删除记录

```http
DELETE /api/scan/{scan_id}/delete

POST /api/history/batch-delete
{
  "scan_ids": ["id1", "id2", "id3"]
}
```

---

## 📊 检测规则说明

### 支持的检测类型

| 类型           | 严重等级 | 说明         |
| -------------- | -------- | ------------ |
| `API_KEY`      | HIGH     | API密钥泄露  |
| `SECRET_KEY`   | HIGH     | 密钥泄露     |
| `DB_PASSWORD`  | HIGH     | 数据库密码   |
| `AWS_KEY`      | HIGH     | AWS访问密钥  |
| `PRIVATE_KEY`  | HIGH     | 私钥泄露     |
| `TOKEN`        | MEDIUM   | Token泄露    |
| `INTERNAL_IP`  | MEDIUM   | 内网IP泄露   |
| `DEBUG_MODE`   | MEDIUM   | 调试模式开启 |
| `EMAIL`        | LOW      | 邮箱地址     |
| `PHONE`        | LOW      | 手机号码     |
| `INTERNAL_URL` | LOW      | 内部URL      |

---

## 🛡️ 安全注意事项

1. **授权扫描**：仅扫描您有权限的目标网站
2. **数据保密**：扫描结果可能包含敏感信息，请妥善保管
3. **合规使用**：遵守当地法律法规和公司安全政策
4. **API密钥**：不要将API密钥提交到代码仓库

---

## 📞 技术支持

遇到问题？请按以下顺序排查：

1. 查看本文档的 [常见问题](#常见问题)
2. 检查终端错误日志
3. 提交Issue到项目仓库

---

## 📋 更新日志

### v2.0 (2026-05-20)

- ✅ 新增AI智能分析功能
- ✅ 新增选择性扫描
- ✅ 新增批量删除历史
- ✅ 修复Windows Unicode编码问题
- ✅ 优化扫描性能
- ✅ 新增Markdown报告导出

---

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

贡献者
