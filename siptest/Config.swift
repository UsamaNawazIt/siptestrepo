import Foundation

struct Config {
  let wssUrl: URL
  let domain: String
  let agentId: String
  let userAgent: String
  let origin: String?   // keep nil unless you KNOW it
  let expires: Int
  let instanceId: UUID

  static var current: Config {
    // EDIT HERE ONLY
    Config(
      wssUrl: URL(string: "wss://wrtc-pri.niceincontact.com")!,
      domain: "niceincontact.com",
      agentId: "39572041",
      userAgent: "NICE CXONE SDK CONSUMER: Flutter",
      origin: nil,
      expires: 600,
      instanceId: loadOrCreateInstanceId()
    )
  }

  private static func loadOrCreateInstanceId() -> UUID {
    let key = "sip.instance.uuid"
    if let s = UserDefaults.standard.string(forKey: key),
       let u = UUID(uuidString: s) {
      return u
    }
    let u = UUID()
    UserDefaults.standard.set(u.uuidString, forKey: key)
    return u
  }
}
