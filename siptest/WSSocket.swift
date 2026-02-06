import Foundation
import Network
import CryptoKit

final class WSSocket {
  // Callbacks
  var onOpen: (() -> Void)?
  var onText: ((String) -> Void)?
  var onClose: ((Int?, String?) -> Void)?
  var onError: ((Error) -> Void)?

  // Debug logs
  var onDebug: ((String) -> Void)?

  private let url: URL
  private let host: String
  private let port: UInt16
  private let pathAndQuery: String
  private let subprotocol: String?
  private let origin: String?
  private let userAgent: String?

  private var conn: NWConnection?
  private var readBuffer = Data()

  private var isHandshakeComplete = false
  private var wsKey = ""

  private var pingTimer: DispatchSourceTimer?

  // Fragment reassembly (minimal)
  private var fragOpcode: UInt8?
  private var fragData = Data()

  init(url: URL, subprotocol: String? = "sip", origin: String? = nil, userAgent: String? = nil) {
    self.url = url
    self.host = url.host ?? ""
    self.port = UInt16(url.port ?? 443)

    let path = url.path.isEmpty ? "/" : url.path
    self.pathAndQuery = path + (url.query.map { "?\($0)" } ?? "")

    self.subprotocol = subprotocol
    self.origin = origin
    self.userAgent = userAgent
  }

  func connect() {
    let tls = NWProtocolTLS.Options()
    let params = NWParameters(tls: tls)
    params.allowLocalEndpointReuse = true
    params.includePeerToPeer = false

    let endpoint = NWEndpoint.hostPort(host: .init(host), port: .init(integerLiteral: port))
    let c = NWConnection(to: endpoint, using: params)
    self.conn = c

    c.stateUpdateHandler = { [weak self] state in
      guard let self else { return }
      switch state {
      case .ready:
        self.debug("NWConnection ready: TLS established to \(self.host):\(self.port)")
        self.startHandshake()
      case .failed(let err):
        self.fail(err)
      case .cancelled:
        self.debug("NWConnection cancelled")
        self.stopPing()
      default:
        break
      }
    }

    c.start(queue: .global(qos: .userInitiated))
  }

  func sendText(_ text: String) {
    guard isHandshakeComplete else {
      debug("sendText ignored (handshake not complete)")
      return
    }
    let frame = WSFrame.text(text).encodeClient()
    sendRaw(frame)
  }

  func close(code: UInt16 = 1000, reason: String? = nil) {
    guard isHandshakeComplete else {
      conn?.cancel()
      return
    }
    var payload = Data()
    payload.append(contentsOf: withUnsafeBytes(of: code.bigEndian, Array.init))
    if let reason, let d = reason.data(using: .utf8) { payload.append(d) }
    sendRaw(WSFrame.close(payload).encodeClient())
    conn?.cancel()
  }

  func startPing(every seconds: TimeInterval = 25) {
    stopPing()
    let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
    t.schedule(deadline: .now() + seconds, repeating: seconds)
    t.setEventHandler { [weak self] in
      self?.ping()
    }
    pingTimer = t
    t.resume()
  }

  func stopPing() {
    pingTimer?.cancel()
    pingTimer = nil
  }

  func ping() {
    guard isHandshakeComplete else { return }
    let payload = Data((0..<4).map { _ in UInt8.random(in: 0...255) })
    sendRaw(WSFrame.ping(payload).encodeClient())
    debug("WS -> PING (\(payload.count) bytes)")
  }

  // MARK: - Handshake

  private func startHandshake() {
    wsKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()

    var headers: [String: String] = [
      "Host": host,
      "Upgrade": "websocket",
      "Connection": "Upgrade",
      "Sec-WebSocket-Key": wsKey,
      "Sec-WebSocket-Version": "13"
    ]

    if let subprotocol {
      headers["Sec-WebSocket-Protocol"] = subprotocol
    }
    if let origin {
      headers["Origin"] = origin
    }
    if let userAgent {
      headers["User-Agent"] = userAgent
    }

    var req = "GET \(pathAndQuery) HTTP/1.1\r\n"
    for (k, v) in headers {
      req += "\(k): \(v)\r\n"
    }
    req += "\r\n"

    debug("=== WS UPGRADE REQUEST ===\n\(req)========================")
    sendRaw(Data(req.utf8))

    receiveLoop()
  }

  private func handleHandshakeBytes() {
    guard let range = readBuffer.range(of: Data("\r\n\r\n".utf8)) else { return }

    let headerData = readBuffer.subdata(in: 0..<range.upperBound)
    readBuffer.removeSubrange(0..<range.upperBound)

    guard let headerStr = String(data: headerData, encoding: .utf8) else {
      fail(NSError(domain: "WSSocket", code: -1, userInfo: [NSLocalizedDescriptionKey: "Handshake response not UTF-8"]))
      return
    }

    debug("=== WS UPGRADE RESPONSE ===\n\(headerStr)========================")

    let firstLine = headerStr.split(separator: "\r\n").first.map(String.init) ?? ""
    guard firstLine.hasPrefix("HTTP/1.1 101") || firstLine.hasPrefix("HTTP/1.0 101") else {
      fail(NSError(domain: "WSSocket", code: -2, userInfo: [NSLocalizedDescriptionKey: "Handshake failed: \(firstLine)"]))
      return
    }

    let accept = extractHeader("Sec-WebSocket-Accept", from: headerStr)
    let expected = computeAccept(for: wsKey)
    guard accept == expected else {
      fail(NSError(domain: "WSSocket", code: -3, userInfo: [NSLocalizedDescriptionKey: "Bad Sec-WebSocket-Accept"]))
      return
    }

    // If server returns Sec-WebSocket-Protocol, you can optionally validate it:
    if let sp = subprotocol {
      if let serverSP = extractHeader("Sec-WebSocket-Protocol", from: headerStr),
         serverSP.lowercased() != sp.lowercased() {
        debug("Warning: server subprotocol mismatch: \(serverSP) (expected \(sp))")
      }
    }

    isHandshakeComplete = true
    debug("WS handshake complete ✅")
    onOpen?()

    // Parse any remaining bytes as WS frames
    parseFrames()
  }

  private func computeAccept(for key: String) -> String {
    let guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    let input = Data((key + guid).utf8)
    let hash = Insecure.SHA1.hash(data: input)
    return Data(hash).base64EncodedString()
  }

  private func extractHeader(_ name: String, from response: String) -> String? {
    for rawLine in response.split(separator: "\r\n") {
      let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
      if line.lowercased().hasPrefix(name.lowercased() + ":") {
        return line.split(separator: ":", maxSplits: 1).last?
          .trimmingCharacters(in: .whitespacesAndNewlines)
      }
    }
    return nil
  }

  // MARK: - Receive / Parse

  private func receiveLoop() {
    conn?.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, err in
      guard let self else { return }

      if let err {
        self.fail(err)
        return
      }

      if let data, !data.isEmpty {
        self.readBuffer.append(data)

        if !self.isHandshakeComplete {
          self.handleHandshakeBytes()
        } else {
          self.parseFrames()
        }
      }

      if isComplete {
        self.debug("NWConnection closed by peer")
        self.stopPing()
        self.onClose?(nil, "socket closed")
        return
      }

      self.receiveLoop()
    }
  }

  private func parseFrames() {
    while true {
      guard let (frame, consumed) = WSFrame.decodeServer(from: readBuffer) else { return }
      readBuffer.removeSubrange(0..<consumed)

      switch frame {
      case .text(let s, let fin):
        handleTextFragment(opcode: 0x1, text: s, fin: fin)

      case .continuation(let data, let fin):
        handleContinuation(data: data, fin: fin)

      case .ping(let d):
        debug("WS <- PING (\(d.count) bytes) ; replying PONG")
        sendRaw(WSFrame.pong(d).encodeClient())

      case .pong(let d):
        debug("WS <- PONG (\(d.count) bytes)")

      case .close(let payload):
        let (code, reason) = parseClosePayload(payload)
        debug("WS <- CLOSE code=\(code.map(String.init) ?? "nil") reason=\(reason ?? "nil")")
        stopPing()
        onClose?(code, reason)
        conn?.cancel()
        return

      case .binary:
        // Not needed for this proof
        break
      }
    }
  }

  private func handleTextFragment(opcode: UInt8, text: String, fin: Bool) {
    let d = Data(text.utf8)
    if fin {
      onText?(text)
      return
    }
    // start fragment
    fragOpcode = opcode
    fragData = d
  }

  private func handleContinuation(data: Data, fin: Bool) {
    guard fragOpcode != nil else { return }
    fragData.append(data)
    if fin {
      if let s = String(data: fragData, encoding: .utf8) {
        onText?(s)
      }
      fragOpcode = nil
      fragData = Data()
    }
  }

  private func parseClosePayload(_ payload: Data) -> (Int?, String?) {
    if payload.count >= 2 {
      let code = Int(UInt16(bigEndian: payload.withUnsafeBytes { $0.load(as: UInt16.self) }))
      let reasonData = payload.count > 2 ? payload.subdata(in: 2..<payload.count) : Data()
      let reason = reasonData.isEmpty ? nil : String(data: reasonData, encoding: .utf8)
      return (code, reason)
    }
    return (nil, nil)
  }

  // MARK: - Send / Errors

  private func sendRaw(_ data: Data) {
    conn?.send(content: data, completion: .contentProcessed { [weak self] err in
      if let err { self?.fail(err) }
    })
  }

  private func fail(_ err: Error) {
    debug("WS ERROR: \(err)")
    stopPing()
    onError?(err)
    conn?.cancel()
  }

  private func debug(_ msg: String) {
    onDebug?(msg)
  }
}

// MARK: - WebSocket frame encoding/decoding (minimal but correct)

private enum WSFrame {
  case text(String)
  case binary(Data)
  case continuation(Data)
  case ping(Data)
  case pong(Data)
  case close(Data)

  // Decode result includes FIN bit for text/continuation (needed for fragmentation).
  enum Decoded {
    case text(String, fin: Bool)
    case binary(Data, fin: Bool)
    case continuation(Data, fin: Bool)
    case ping(Data)
    case pong(Data)
    case close(Data)
  }

  func encodeClient() -> Data {
    let (opcode, payload): (UInt8, Data) = {
      switch self {
      case .text(let s): return (0x1, Data(s.utf8))
      case .binary(let d): return (0x2, d)
      case .continuation(let d): return (0x0, d)
      case .close(let d): return (0x8, d)
      case .ping(let d): return (0x9, d)
      case .pong(let d): return (0xA, d)
      }
    }()

    var out = Data()
    out.append(0x80 | opcode) // FIN=1 (we only send unfragmented frames here)

    let maskBit: UInt8 = 0x80
    let len = payload.count

    if len <= 125 {
      out.append(maskBit | UInt8(len))
    } else if len <= 0xFFFF {
      out.append(maskBit | 126)
      out.append(contentsOf: withUnsafeBytes(of: UInt16(len).bigEndian, Array.init))
    } else {
      out.append(maskBit | 127)
      out.append(contentsOf: withUnsafeBytes(of: UInt64(len).bigEndian, Array.init))
    }

    var mask = (0..<4).map { _ in UInt8.random(in: 0...255) }
    out.append(contentsOf: mask)

    var masked = Data(count: len)
    for i in 0..<len {
      masked[i] = payload[i] ^ mask[i % 4]
    }
    out.append(masked)
    return out
  }

  static func decodeServer(from buffer: Data) -> (frame: Decoded, consumed: Int)? {
    if buffer.count < 2 { return nil }
    let b0 = buffer[0]
    let b1 = buffer[1]

    let fin = (b0 & 0x80) != 0
    let opcode = b0 & 0x0F
    let masked = (b1 & 0x80) != 0

    var len = Int(b1 & 0x7F)
    var off = 2

    if len == 126 {
      if buffer.count < off + 2 { return nil }
      let v: UInt16 = buffer.subdata(in: off..<off+2).withUnsafeBytes { $0.load(as: UInt16.self) }
      len = Int(UInt16(bigEndian: v))
      off += 2
    } else if len == 127 {
      if buffer.count < off + 8 { return nil }
      let v: UInt64 = buffer.subdata(in: off..<off+8).withUnsafeBytes { $0.load(as: UInt64.self) }
      let be = UInt64(bigEndian: v)
      if be > UInt64(Int.max) { return nil }
      len = Int(be)
      off += 8
    }

    var maskKey: [UInt8] = []
    if masked {
      if buffer.count < off + 4 { return nil }
      maskKey = Array(buffer[off..<off+4])
      off += 4
    }

    if buffer.count < off + len { return nil }

    var payload = buffer.subdata(in: off..<off+len)
    let consumed = off + len

    if masked, !maskKey.isEmpty {
      for i in 0..<payload.count {
        payload[i] = payload[i] ^ maskKey[i % 4]
      }
    }

    switch opcode {
    case 0x0:
      return (.continuation(payload, fin: fin), consumed)
    case 0x1:
      let s = String(data: payload, encoding: .utf8) ?? ""
      return (.text(s, fin: fin), consumed)
    case 0x2:
      return (.binary(payload, fin: fin), consumed)
    case 0x8:
      return (.close(payload), consumed)
    case 0x9:
      return (.ping(payload), consumed)
    case 0xA:
      return (.pong(payload), consumed)
    default:
      return nil
    }
  }
}
