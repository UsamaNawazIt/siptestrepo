import Foundation

final class SipUARegisterOnly {
  enum ResultState {
    case idle
    case connecting
    case open
    case registered(code: Int, reason: String)
    case failed(reason: String)
    case timeout
  }

  var onRegistered: ((Int, String) -> Void)?
  var onRegisterFailed: ((String) -> Void)?
  var onLog: ((String) -> Void)?

  private let socket: WSSocket
  private let registerPayload: String
  private let timeoutSeconds: TimeInterval

  private var timeoutTimer: DispatchSourceTimer?
  private var gotAnySipResponse = false

  init(socket: WSSocket, registerPayload: String, timeoutSeconds: TimeInterval = 10) {
    self.socket = socket
    self.registerPayload = registerPayload
    self.timeoutSeconds = timeoutSeconds
    wire()
  }

  func start() {
    log("UA: starting connect()")
    startTimeout()
    socket.connect()
  }

  func stop() {
    timeoutTimer?.cancel()
    timeoutTimer = nil
    socket.close()
  }

  private func wire() {
    socket.onDebug = { [weak self] s in self?.log(s) }

    socket.onOpen = { [weak self] in
      guard let self else { return }
      self.log("UA: WS open ✅ — sending REGISTER")
      self.log("=== FIRST REGISTER ===\n\(self.registerPayload)====================")
      self.socket.sendText(self.registerPayload)
      self.socket.startPing(every: 25)
    }

    socket.onText = { [weak self] text in
      guard let self else { return }
      self.gotAnySipResponse = true
      self.log("=== FIRST SIP RESPONSE (raw) ===\n\(text)\n====================")

      guard let msg = SipMessage.parse(text) else {
        self.fail("SIP parse failed (empty/invalid)")
        return
      }

      if msg.isResponse, msg.cseq.method?.uppercased() == "REGISTER", msg.cseq.number == 1 {
        if let code = msg.statusCode {
          if code == 200 {
            self.success(code: code, reason: msg.reasonPhrase.isEmpty ? "OK" : msg.reasonPhrase)
          } else {
            self.fail("REGISTER failed: \(code) \(msg.reasonPhrase)")
          }
        } else {
          self.fail("REGISTER response missing status code")
        }
      } else {
        self.log("UA: received non-REGISTER SIP (ignored). startLine=\(msg.startLine)")
      }
    }

    socket.onClose = { [weak self] code, reason in
      guard let self else { return }
      self.log("UA: WS closed. code=\(code.map(String.init) ?? "nil") reason=\(reason ?? "nil")")
      if !self.gotAnySipResponse {
        self.fail("Socket closed before SIP response")
      }
    }

    socket.onError = { [weak self] err in
      self?.fail("Socket error: \(err.localizedDescription)")
    }
  }

  private func startTimeout() {
    timeoutTimer?.cancel()
    let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
    t.schedule(deadline: .now() + timeoutSeconds)
    t.setEventHandler { [weak self] in
      guard let self else { return }
      if !self.gotAnySipResponse {
        self.log("⏳ TIMEOUT: no SIP response in \(Int(self.timeoutSeconds))s")
        self.onRegisterFailed?("Timeout: no SIP response in \(Int(self.timeoutSeconds))s")
        self.socket.close()
      }
    }
    timeoutTimer = t
    t.resume()
  }

  private func success(code: Int, reason: String) {
    timeoutTimer?.cancel()
    timeoutTimer = nil
    log("✅ REGISTERED: \(code) \(reason)")
    onRegistered?(code, reason)
  }

  private func fail(_ reason: String) {
    timeoutTimer?.cancel()
    timeoutTimer = nil
    log("❌ FAILED: \(reason)")
    onRegisterFailed?(reason)
  }

  private func log(_ s: String) {
    onLog?(s)
    print(s)
  }
}
