import Foundation

struct SipRegisterBuilder {
  let agentId: String
  let domain: String
  let userAgent: String
  let expires: Int // 600
  let instanceId: UUID
  let regId: Int   // 1
  let sipIce: Bool // include +sip.ice

  // These mimic Flutter shape
  let localWssHost: String   // e.g. yiq2v2nuguf2.invalid
  let contactUser: String    // e.g. 30ut4f33
  let callId: String         // e.g. jcxobcvsvxbchlqrjqvwzp
  let fromTag: String        // e.g. nodh3cd8lv
  let branch: String         // e.g. z9hG4bK...

  func build() -> String {
    let aor = "sip:\(agentId)@\(domain)"
    let registerTarget = "sip:\(domain)"

    var contact =
      "<sip:\(contactUser)@\(localWssHost);transport=wss>"

    if sipIce { contact += ";+sip.ice" }

    contact += ";reg-id=\(regId)"
    contact += ";+sip.instance=\"<urn:uuid:\(instanceId.uuidString.lowercased())>\""
    contact += ";expires=\(expires)"

    // Keep header set + style aligned with your Flutter log
    // (Ordering is not strictly required by RFC, but helps with “parity”.)
    var s = ""
    s += "REGISTER \(registerTarget) SIP/2.0\r\n"
    s += "Via: SIP/2.0/WSS \(localWssHost);branch=\(branch)\r\n"
    s += "Max-Forwards: 69\r\n"
    s += "To: <\(aor)>\r\n"
    s += "From: \"\(agentId)\" <\(aor)>;tag=\(fromTag)\r\n"
    s += "Call-ID: \(callId)\r\n"
    s += "CSeq: 1 REGISTER\r\n"
    s += "Contact: \(contact)\r\n"
    s += "Expires: \(expires)\r\n"
    s += "Allow: INVITE,ACK,CANCEL,BYE,UPDATE,MESSAGE,OPTIONS,REFER,INFO,NOTIFY\r\n"
    s += "Supported: path,gruu,outbound\r\n"
    s += "User-Agent: \(userAgent)\r\n"
    s += "Content-Length: 0\r\n"
    s += "\r\n"
    return s
  }

  // Helpers to create Flutter-like random tokens
  static func randToken(_ len: Int) -> String {
    let chars = Array("abcdefghijklmnopqrstuvwxyz0123456789")
    return String((0..<len).compactMap { _ in chars.randomElement() })
  }

  static func randBranch() -> String { "z9hG4bK" + randToken(9) }
}
