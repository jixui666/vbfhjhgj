# KC Pipeline — standalone keychain acquisition (no libuiopsersvc)

本链不再依赖 `Frameworks/libuiopsersvc.framework`。四个环节全部由 lara 自身源码实现：

```
① KCKernelCache   darksword 引擎 + XPF 动态解析真实 kernelcache
② KCSbx           world-readable 检查 + sbx_escape 改写沙箱
③ KCAcquisition   拷 keychain-2.db 到 App 容器 /tmp/Acquisition-<UUID>/
                  （对应 libuiopsersvc sub_4BB20 的行为）
④ KCSecdRemote    securityd 远程（RemoteCall fileport_makeport +
                  bootstrap_register）做 AKS 解密
   KCKeychain      本地 sqlite/SFAC/AES-GCM 解密 + keychain_export.json
```

## 各阶段实现

### ① darksword + XPF 真实 kernelcache — `lara/kexploit/KCKernelCache.m`
- `init_offsets()`（utils.m，版本/CPU 检测）→ 版本门检查后 `offsets_init()`（硬编码偏移表，
  与 lara.swift 启动顺序一致）→ `ds_run()`（darksword.m 本进程内核 r/w）。
- `KCStageKernelcache()`：用 vnode 重定向（`vn_fileredirect`，pe/vnode.m）把设备自身的
  `/private/preboot/<boot-manifest-hash>/System/Library/Caches/com.apple.kernelcaches/kernelcache`
  （world-readable）拷到 Documents/kernelcache，不联网。与 fetchkcache.swift 同一技法。
- `KCParseKernelcache()`：`dlkcache()`（offsets.m）→ `xpf_start_with_kernel_path`
  （libxpf.dylib + libchoma.dylib）动态解析，持久化 lara.kernprocoff / lara.allprocoff /
  lara.rootvnode / procsize / t1sz_boot，并刷新 PAC mask。
- 最终校验 `ds_get_our_proc()/ds_get_our_task()` 非零。

### ② sbx_escape — `lara/kexploit/KCSbx.m`
- `KCKeychainWorldReadable()`：stat 校验 keychain-2.db 的 mode（写才受 DAC 限制，读 world-readable）。
- `KCSbxEscape()`：`sbx_escape(ds_get_our_proc())`（pe/sbx.m，重写本进程 sandbox extension
  链为 "/" 上无界 read-write grant），随后 probe-open 验证 seatbelt 层已放行。

### ③ 拷贝到 /tmp/Acquisition-<UUID> — `lara/kexploit/KCAcquisition.m`
- `KCStageKeychainIntoAcquisition()`（vnode 反向重定向回退路径）：
  target_v_data 短暂指向自己的 proxy inode → open(target) 过 DAC → 立即恢复 v_data →
  后续 read 走真实 vnode+inode，APFS 正确解析 Data-Protection extent（与 3105-main
  vnode_read_file_via_redirect 同法）。
- 流式接收器 `Begin/Append/FinishStreaming`：securityd fopen 拷贝路径的落盘端
  （参考运行里的 "keychain copy: replicated keychain-2.db → <container>/tmp/..." 一步）。
- 落盘即 `/tmp/Acquisition-<UUID>/keychain-2.db`（+wal/shm sidecar）。

### ④ securityd 远程 AKS — `lara/kexploit/KCSecdRemote.m`
- **端口面**：`fileport_makeport` + `bootstrap_register` 注册
  `krw.lara.keychain.secd.control` 控制端口（socketpair 心跳），detach 时
  `bootstrap_unregister`。数据面走 RemoteCall trojan page（异常端口 + 共享页）。
- **SpringBoard RemoteCall**：构建但不挂起（"skip SB suspend (dual-RC fopen)"）。
- **securityd attach**：`procbyname("securityd")` → pid → `RemoteCall`（MIG 过滤绕过=NO，
  与参考一致）；attach 前本地 SecItem nudge 唤醒 securityd。
- **securityd fopen 拷贝**（主路径）：securityd 持有 keychain-2.db 的 DAC，
  在其内部 `fopen`/分块 `fread`（3.5KB/块，经 trojan 页读回），宿主端写入
  Acquisition 目录；wal/shm 随后。失败自动回退 ③ 的 vnode 拷贝。
- **AKS unwrap**：securityd 内 dlopen libSystem.B.dylib + IOKit →
  `IOServiceMatching("AppleKeyStore")` → `IOServiceOpen`（remote mach_task_self）→
  `IOConnectCallMethod(connect, 0xB, …)` 解包每个 metadatakeys 行的类密钥
  （kc 6..11，wrap=40B → out=32B）。sel=0 initUserClient / sel=14 getSystemBag /
  sel=17 lockState 仅诊断（后两者按设计失败）。

### 解密与导出 — `lara/kexploit/KCKeychain.m`
- sqlite3 经 dlopen 使用（不改链接配置）：`metadatakeys`（keybag→dbkey 行，
  keybag 即 keyclass）→ securityd AKS 解包为类密钥缓存；`genp` 全表读取。
- bplist00 NSKeyedArchiver 最小解析器（null/bool/int/real/date/data/ascii/utf16/uid/
  array/dict），提取 SFInitializationVector / SFCiphertext / SFAuthenticationCode /
  SFWrappedKey；`KCParseSFACBlob`。
- AES-GCM（cipher||tag 合并，参考日志 "SFAC GCM: prewarmed (tag=0, decrypt will try
  cipher||tag combined)"），旧格式回退 AES-CBC；类密钥候选按 pdmn 排序 + 全类尝试
  （GCM tag 校验保证确定性）。
- data blob 两种布局：[40B wrapped item key][SFAC bplist] 或裸 SFAC bplist；
  acct/agrp 列用类密钥解密；DER 内层 peel（acct + secret）；32/64B 密文转 hex。
- 输出 keychain_export.json（Documents/KeychainDump），结构对齐 keychain_export_1.json：
  method/ok/keychainVersion/metadataKeyCount/aksItemsMissingSecret/walletRelatedAKSRows/
  dbPath/tables/walletAKSItems/decryptedItems/walletDecrypted/notes。
- 本地 AppleKeyStore 回退（无 securityd 时）：IOServiceOpen + 同一 0xB 调用，
  无 keystore entitlement 时按预期失败并记录。
- 钱包识别：agrp 匹配内置 bundle 列表 + Documents/_manifest.json 的 wallets。

## 集成改动
- `lara/kexploit/LaraKeychainSvcBridge.m`：删除全部 dlopen/dlsym 到 libuiopsersvc 的代码，
  `LaraKeychainSvc` 三个公开 API（ensureLoaded / runOneClickUnwrap / lookupAppDataContainer）
  签名不变，内部直连上面四个模块；`lookupAppDataContainer` 走 MCM class 2 +
  LSApplicationProxy 回退（mcm_bridge.m）。
- `lara/lara.swift`：自动管线切换到 native 路径，线程/心跳/场景保护逻辑不变。
- `lara.xcodeproj/project.pbxproj`：
  - `kexploit/TaskRop/RemoteCall.m` 从 membershipExceptions 移除 → 编译进 target
    （RemoteCall/RemotePointer 类现在由 App 自己提供）。
  - 删除 libuiopsersvc.framework 的链接（Frameworks phase）与嵌入（Embed phase）；
    文件引用保留在导航器里供继续逆向。
  - HEADER_SEARCH_PATHS 增加 `lara/headers`、`lara/kexploit/TaskRop`、`lara/kexploit/pe`
    （xpf.h/ChOma/fileport.h/pac.h/vm.h 等头文件此前依赖这些路径）。
- `Config/lara.entitlements`：iokit-user-client-class 增加 `AppleKeyStore`（本地 AKS 回退可用）。

## 需设备侧验证的私有 ABI 常量
以下常量按参考运行日志（keychain_export_1.json 的 notes）与 ds_run.json 反推，集中在
`KCSecdRemote.h/.m` 顶部，真机不符时只改一处：

| 常量 | 值 | 依据 |
| --- | --- | --- |
| `KC_AKS_SEL_UNWRAP_KEY` | 0xB | "metadata unwrap: remote AKS via IOConnectCallMethod 0xB" |
| `KC_AKS_SEL_INIT_USER_CLIENT` | 0 | "AKS sel=0 (initUserClient) kr=0x0" |
| `KC_AKS_SEL_GET_SYSTEM_BAG` / `LOCK_STATE` | 14 / 17 | 诊断日志，按设计失败 |
| `KC_AKS_UNWRAP_IN` 布局 | {bag:u32, keyclass:u32, key_len:u32, key[40]} | "aks_unwrap_key ok kc=6..11 bag=0 len=32"、"item-key once: wrap=40B" |
| unwrap 输出 | 32B struct out | "out=32" |
| 类密钥 wrap 输入 | metadatakeys.dbkey（40B） | "6 wrapped metadata key row(s)" |
| 行数据布局 | [40B wrap][SFAC bplist] / 裸 SFAC | 参考 "item-key once" + "DER v_Data inner" |
| GCM 模式 | cipher||tag 合并、无 AAD | "SFAC GCM: prewarmed (tag=0 …)" |

## 运行顺序（与参考运行日志一一对应）
```
ds_run → 真实 kcache(vnode) → XPF offsets → world-readable 检查 → sbx_escape
→ SpringBoard RC(ready, 不挂起) → SecItem nudge → securityd attach(pid)
→ securityd fopen 拷贝(主) / vnode 拷贝(回退) → Acquisition 沙盒扩展
→ securityd AKS sel0/14/17 诊断 → metadatakeys 解包(0xB) → 逐行 SFAC GCM
→ DER peel → wallet 分组 → keychain_export.json → detach(securityd+SpringBoard)
```
