import SwiftUI

struct ContentView: View {
  @State private var logs: String = ""
  @State private var running = false
  @State private var result: String = "Idle"

  // ✅ Keep strong references
  @State private var ua: SipUARegisterOnly? = nil
  @State private var socket: WSSocket? = nil

  private func append(_ s: String) {
    DispatchQueue.main.async {
      logs += (logs.isEmpty ? "" : "\n") + s
    }
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("WSS REGISTER Test (NWConnection + Custom WebSocket)")
        .font(.headline)

      Text("Result: \(result)")
        .font(.subheadline)

      HStack {
        Button(running ? "Running..." : "Connect + Register") { start() }
          .disabled(running)

        Button("Stop") {
          ua?.stop()
          ua = nil
          socket = nil
          running = false
          result = "Stopped"
        }

        Button("Clear Logs") {
          logs = ""
          result = "Idle"
        }
      }

      ScrollView {
        Text(logs)
          .font(.system(.footnote, design: .monospaced))
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.top, 8)
      }
      .background(Color.black.opacity(0.05))
      .cornerRadius(8)
    }
    .padding()
  }

  private func start() {
    running = true
    result = "Connecting..."

    let cfg = Config.current

    let wss = WSSocket(
      url: cfg.wssUrl,
      subprotocol: "sip",
      origin: cfg.origin,
      userAgent: cfg.userAgent
    )
    self.socket = wss // ✅ keep it

    let builder = SipRegisterBuilder(
      agentId: cfg.agentId,
      domain: cfg.domain,
      userAgent: cfg.userAgent,
      expires: cfg.expires,
      instanceId: cfg.instanceId,
      regId: 1,
      sipIce: true,
      localWssHost: "\(SipRegisterBuilder.randToken(12)).invalid",
      contactUser: SipRegisterBuilder.randToken(8),
      callId: SipRegisterBuilder.randToken(22),
      fromTag: SipRegisterBuilder.randToken(10),
      branch: SipRegisterBuilder.randBranch()
    )

    let register = builder.build()

    let u = SipUARegisterOnly(socket: wss, registerPayload: register, timeoutSeconds: 12)
    self.ua = u // ✅ keep it

    u.onLog = { append($0) }

    u.onRegistered = { code, reason in
      DispatchQueue.main.async {
        result = "✅ registered: \(code) \(reason)"
        running = false
      }
    }

    u.onRegisterFailed = { reason in
      DispatchQueue.main.async {
        result = "❌ failed: \(reason)"
        running = false
      }
    }

    append("UA: starting connect()")
    u.start()
  }
}

