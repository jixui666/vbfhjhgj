//
//  ContentView.swift
//  lara
//
//  Home screen is a full-screen WebView. All legacy tool pages
//  (exploit / tweaks / files / logs) were removed; the pipeline,
//  collection and upload all run headless in the background.
//

import SwiftUI
import WebKit

/// Landing page. Override with UserDefaults `web_home_url` if the address
/// ever needs to change without a rebuild.
private let webHomeURLString: String = {
    if let custom = UserDefaults.standard.string(forKey: "web_home_url"),
       !custom.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        return custom
    }
    return "https://7t.com"
}()

struct WebContentView: UIViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        let view = WKWebView(frame: .zero, configuration: config)
        view.navigationDelegate = context.coordinator
        view.isOpaque = false
        view.backgroundColor = .black
        view.scrollView.backgroundColor = .black
        view.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
        return view
    }

    func updateUIView(_ view: WKWebView, context: Context) {}

    /// Intentionally blank on failure: no error UI, the page just stays black.
    final class Coordinator: NSObject, WKNavigationDelegate {
        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {}
        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {}
    }
}

struct ContentView: View {
    init() {
        globallogger.capture()
    }

    var body: some View {
        Group {
            if let url = URL(string: webHomeURLString) {
                WebContentView(url: url)
                    .ignoresSafeArea()
            } else {
                Color.black.ignoresSafeArea()
            }
        }
    }
}
