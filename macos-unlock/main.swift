import Foundation
import LocalAuthentication
import Security
import Network

struct Config {
    let service = "com.password-manager-go.master"
    let account = "default"
    let tokenURL: URL
    let helperPort: UInt16 = 9797
    let userEmail: String

    init() {
        let env = ProcessInfo.processInfo.environment["PM_SERVER_URL"]
            ?? "https://127.0.0.1:8443/auth/biometric-token"
        self.tokenURL = URL(string: env) ?? URL(string: "https://127.0.0.1:8443/auth/biometric-token")!
        self.userEmail = ProcessInfo.processInfo.environment["PM_USER_EMAIL"] ?? ""
    }
}

func biometricsAvailable() -> Bool {
    let ctx = LAContext()
    var err: NSError?
    return ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
}

func readMasterPassword(config: Config, context: LAContext) throws -> String {
    context.localizedReason = "Authenticate to unlock master password"

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: config.service,
        kSecAttrAccount as String: config.account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationContext as String: context
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status != errSecSuccess {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                      userInfo: [NSLocalizedDescriptionKey: "Keychain item not found or access denied"])
    }
    guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
        throw NSError(domain: "unlock", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid keychain data"])
    }
    return value
}

func requestToken(master: String, config: Config) throws -> String {
    var request = URLRequest(url: config.tokenURL)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    let email = config.userEmail.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
    let pass = master.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
    let body = "email=" + email + "&master_password=" + pass
    request.httpBody = body.data(using: .utf8)

    let semaphore = DispatchSemaphore(value: 0)
    var resultError: Error?
    var responseData: Data?
    var statusCode: Int = 0

    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        if let error = error {
            resultError = error
        } else if let http = response as? HTTPURLResponse {
            statusCode = http.statusCode
            responseData = data
        }
        semaphore.signal()
    }
    task.resume()
    semaphore.wait()

    if let err = resultError {
        throw NSError(domain: "unlock", code: 5,
                      userInfo: [NSLocalizedDescriptionKey:
                        "Could not connect to the server at \(config.tokenURL).\n\(err.localizedDescription)"])
    }

    guard (200...399).contains(statusCode) else {
        throw NSError(domain: "unlock", code: statusCode,
                      userInfo: [NSLocalizedDescriptionKey: "Server returned \(statusCode)"])
    }

    guard
        let data = responseData,
        let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let token = json["token"] as? String
    else {
        throw NSError(domain: "unlock", code: 4,
                      userInfo: [NSLocalizedDescriptionKey: "Invalid token response"])
    }

    return token
}

func handleUnlockRequest(config: Config) -> (Int, String) {
    do {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw error ?? NSError(domain: "unlock", code: 2,
                                  userInfo: [NSLocalizedDescriptionKey: "Biometrics not available"])
        }
        let semaphore = DispatchSemaphore(value: 0)
        var resultError: Error?
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock password manager") { success, err in
            if !success {
                resultError = err ?? NSError(domain: "unlock", code: 3,
                                             userInfo: [NSLocalizedDescriptionKey: "Biometric auth failed"])
            }
            semaphore.signal()
        }
        semaphore.wait()
        if let err = resultError {
            throw err
        }
        let master = try readMasterPassword(config: config, context: context)
        let token = try requestToken(master: master, config: config)
        return (200, "{\"token\":\"\(token)\"}")
    } catch {
        return (500, "{\"error\":\"\(error.localizedDescription)\"}")
    }
}

func serve(config: Config) throws {
    let listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: config.helperPort)!)
    listener.newConnectionHandler = { connection in
        connection.start(queue: .global())
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, _, _ in
            guard let data = data, let request = String(data: data, encoding: .utf8) else {
                connection.cancel()
                return
            }

            let lines = request.split(separator: "\r\n", omittingEmptySubsequences: false)
            let requestLine = String(lines.first ?? "")

            let originHeader = lines.first(where: { $0.lowercased().hasPrefix("origin:") }) ?? ""
            let origin = originHeader
                .split(separator: ":", maxSplits: 1, omittingEmptySubsequences: true)
                .dropFirst()
                .joined(separator: ":")
                .trimmingCharacters(in: .whitespaces)

            func originAllowed(_ o: String) -> Bool {
                if o.hasPrefix("http://localhost:") { return true }
                if o.hasPrefix("http://127.0.0.1:") { return true }
                if o.hasPrefix("https://localhost:") { return true }
                if o.hasPrefix("https://127.0.0.1:") { return true }
                return false
            }

            func respond(status: Int, body: String) {
                let originValue = originAllowed(origin) ? origin : "https://localhost:8443"
                let response = """
HTTP/1.1 \(status) OK\r
Access-Control-Allow-Origin: \(originValue)\r
Access-Control-Allow-Methods: GET, POST, OPTIONS\r
Access-Control-Allow-Headers: Content-Type\r
Content-Type: application/json\r
Content-Length: \(body.utf8.count)\r
\r
\(body)
"""
                connection.send(content: response.data(using: .utf8),
                                completion: .contentProcessed({ _ in connection.cancel() }))
            }

            if requestLine.hasPrefix("OPTIONS ") {
                respond(status: 200, body: "{}")
                return
            }

            if requestLine.hasPrefix("GET /status ") {
                let ok = true
                let bio = biometricsAvailable()
                respond(status: 200, body: "{\"ok\":\(ok),\"biometrics\":\(bio)}")
                return
            }

            if requestLine.hasPrefix("POST /unlock ") {
                let result = handleUnlockRequest(config: config)
                respond(status: result.0, body: result.1)
                return
            }

            respond(status: 404, body: "{\"error\":\"not found\"}")
        }
    }
    listener.start(queue: .global())
    dispatchMain()
}

let config = Config()

if CommandLine.arguments.contains("--server") {
    do { try serve(config: config) }
    catch { fputs("Server failed: \(error.localizedDescription)\n", stderr); exit(1) }
} else {
    do {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw error ?? NSError(domain: "unlock", code: 2,
                                  userInfo: [NSLocalizedDescriptionKey: "Biometrics not available"])
        }
        let semaphore = DispatchSemaphore(value: 0)
        var resultError: Error?
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock password manager") { success, err in
            if !success {
                resultError = err ?? NSError(domain: "unlock", code: 3,
                                             userInfo: [NSLocalizedDescriptionKey: "Biometric auth failed"])
            }
            semaphore.signal()
        }
        semaphore.wait()
        if let err = resultError {
            throw err
        }
        let master = try readMasterPassword(config: config, context: context)
        let token = try requestToken(master: master, config: config)
        print("Token: \(token)")
    } catch {
        fputs("Unlock failed: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}
