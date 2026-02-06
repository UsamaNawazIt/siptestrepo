import Foundation

struct SipMessage {
  let startLine: String
  let headers: [String: String] // lowercased keys
  let body: String

  var isResponse: Bool { startLine.uppercased().hasPrefix("SIP/2.0") }

  var statusCode: Int? {
    guard isResponse else { return nil }
    let parts = startLine.split(separator: " ")
    guard parts.count >= 2 else { return nil }
    return Int(parts[1])
  }

  var reasonPhrase: String {
    guard isResponse else { return "" }
    let parts = startLine.split(separator: " ", maxSplits: 2)
    return parts.count == 3 ? String(parts[2]) : ""
  }

  func header(_ name: String) -> String? {
    headers[name.lowercased()]
  }

  var cseq: (number: Int?, method: String?) {
    guard let v = header("cseq") else { return (nil, nil) }
    let parts = v.split(separator: " ")
    let num = parts.first.flatMap { Int($0) }
    let method = parts.count >= 2 ? String(parts[1]) : nil
    return (num, method)
  }

  var callId: String? { header("call-id") }
  var via: String? { header("via") }
  var to: String? { header("to") }
  var from: String? { header("from") }

  static func parse(_ raw: String) -> SipMessage? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty { return nil }

    let normalized = trimmed.replacingOccurrences(of: "\r\n", with: "\n")
    let parts = normalized.components(separatedBy: "\n\n")
    let head = parts.first ?? ""
    let body = parts.count > 1 ? parts.dropFirst().joined(separator: "\n\n") : ""

    let lines = head.split(separator: "\n", omittingEmptySubsequences: false)
    guard let first = lines.first else { return nil }

    var headers: [String: String] = [:]
    for l in lines.dropFirst() {
      let line = String(l).trimmingCharacters(in: .whitespaces)
      if line.isEmpty { continue }
      guard let idx = line.firstIndex(of: ":") else { continue }
      let name = line[..<idx].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
      let value = line[line.index(after: idx)...].trimmingCharacters(in: .whitespacesAndNewlines)
      if headers[name] == nil { headers[name] = value }
    }

    return SipMessage(
      startLine: String(first).trimmingCharacters(in: .whitespacesAndNewlines),
      headers: headers,
      body: body
    )
  }

  // Serialize request with \r\n line endings
  static func buildRequest(
    method: String,
    uri: String,
    headers: [(String, String)],
    body: String = ""
  ) -> String {
    var s = ""
    s += "\(method) \(uri) SIP/2.0\r\n"
    for (k, v) in headers {
      s += "\(k): \(v)\r\n"
    }
    if body.isEmpty {
      s += "Content-Length: 0\r\n"
      s += "\r\n"
    } else {
      let bodyBytes = body.data(using: .utf8)?.count ?? 0
      s += "Content-Length: \(bodyBytes)\r\n"
      s += "\r\n"
      s += body
    }
    return s
  }
}
