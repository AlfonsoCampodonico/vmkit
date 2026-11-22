// vmkit-vz: runs one Linux guest on Apple's Virtualization.framework for vmkit's
// `apple-vz` backend (src/apple_vz.rs). vmkit spawns it, one process per VM:
//
//   vmkit-vz --version              prints "vmkit-vz v<version>"
//   vmkit-vz --check                exits 0 if this Mac can run VMs, else prints why and exits 3
//   vmkit-vz --config FILE --api SOCKET
//
// With --config, the helper builds the VM from FILE (JSON, see `Config`), binds the vsock
// sockets, then binds SOCKET last: once SOCKET accepts connections the VM is configured but
// not started. The guest console is the helper's stdout, which vmkit opens in its own
// process (create, append); the helper's own messages go to stderr.
//
// The API takes one JSON line per connection, {"op": "start" | "pause" | "resume"}, and
// answers one line, {"ok": true} or {"ok": false, "error": "..."}, when the operation is done.
//
// Exit codes: 0 when the guest powered off (guestDidStop), 1 when the VM stopped with an
// error, 2 on a configuration error, 3 from --check on a Mac that cannot run VMs.
// SIGKILL is how vmkit ends a VM: the VM's XPC process dies with the helper.
//
// vsock follows Firecracker's hybrid scheme:
//   host-initiated:  connect to <socket>, send "CONNECT <port>\n", read "OK <n>\n", then bytes
//   guest-initiated: the helper connects to <socket>_<port>, where the host listens
// VZ has no wildcard listener, so the guest-initiated ports are a range given in FILE.

import Darwin
import Foundation
import Virtualization

let version = "0.1.0"

// MARK: - Configuration

struct DiskConfig: Decodable {
    let path: String
    let read_only: Bool
}

struct VsockConfig: Decodable {
    /// The host side: host-initiated connections arrive here, guest-initiated ones go to <socket>_<port>.
    let socket: String
    /// Guest-initiated connections are accepted for host ports first...last.
    let first_port: UInt32
    let last_port: UInt32
}

struct Config: Decodable {
    let kernel: String
    let initramfs: String?
    let cmdline: String
    let disks: [DiskConfig]
    let vcpus: Int
    let memory_mib: UInt64
    let vsock: VsockConfig?
}

func die(_ msg: String, code: Int32 = 2) -> Never {
    FileHandle.standardError.write("vmkit-vz: \(msg)\n".data(using: .utf8)!)
    exit(code)
}

func log(_ msg: String) {
    FileHandle.standardError.write("vmkit-vz: \(msg)\n".data(using: .utf8)!)
}

/// A file the VM reads: an existing regular file, never reached through a symlink.
func checkFile(_ path: String, _ what: String) {
    var st = stat()
    guard lstat(path, &st) == 0 else { die("\(what) \(path): \(String(cString: strerror(errno)))") }
    if (st.st_mode & S_IFMT) == S_IFLNK { die("\(what) \(path) is a symlink, which is never followed") }
    if (st.st_mode & S_IFMT) != S_IFREG { die("\(what) \(path) is not a regular file") }
}

// MARK: - Unix sockets

func unixAddr(_ path: String) -> sockaddr_un? {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8)
    guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
    withUnsafeMutableBytes(of: &addr.sun_path) { buf in
        for (i, b) in bytes.enumerated() { buf[i] = b }
    }
    return addr
}

func unixConnect(_ path: String) -> Int32? {
    guard var addr = unixAddr(path) else { return nil }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    if fd < 0 { return nil }
    let rc = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    if rc != 0 { close(fd); return nil }
    return fd
}

func unixListen(_ path: String) -> Int32 {
    guard var addr = unixAddr(path) else { die("socket path too long: \(path)") }
    unlink(path)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    let rc = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    if rc != 0 || listen(fd, 64) != 0 { die("listen on \(path): \(String(cString: strerror(errno)))") }
    return fd
}

/// Accepts connections on `lfd` forever, each handled on a thread of its own.
func acceptLoop(_ lfd: Int32, _ handle: @escaping (Int32) -> Void) {
    Thread.detachNewThread {
        while true {
            let cfd = accept(lfd, nil, nil)
            if cfd < 0 { if errno == EINTR || errno == ECONNABORTED { continue }; break }
            Thread.detachNewThread { handle(cfd) }
        }
    }
}

func writeAll(_ fd: Int32, _ data: [UInt8]) -> Bool {
    var off = 0
    while off < data.count {
        let n = data[off...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        if n < 0 { if errno == EINTR { continue }; return false }
        off += n
    }
    return true
}

/// Reads one line (without the newline), byte by byte so nothing after it is consumed.
func readLine(_ fd: Int32, max: Int = 256) -> String? {
    var line: [UInt8] = []
    var b: UInt8 = 0
    while line.count < max {
        let n = read(fd, &b, 1)
        if n < 0 && errno == EINTR { continue }
        if n <= 0 { return nil }
        if b == UInt8(ascii: "\n") { return String(decoding: line, as: UTF8.self) }
        line.append(b)
    }
    return nil
}

// MARK: - Byte relay

/// Copies bytes both ways between a unix socket and a vsock connection until both directions
/// reach EOF, passing half-close on. Holds the connection (its descriptor is the connection's)
/// until done.
func splice(unix: Int32, conn: VZVirtioSocketConnection) {
    let vfd = conn.fileDescriptor
    let group = DispatchGroup()
    func pump(_ from: Int32, _ to: Int32) {
        group.enter()
        Thread.detachNewThread {
            var buf = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let n = read(from, &buf, buf.count)
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { break }
                if !writeAll(to, Array(buf[0..<n])) { break }
            }
            shutdown(to, SHUT_WR)
            group.leave()
        }
    }
    pump(unix, vfd)
    pump(vfd, unix)
    group.notify(queue: .main) {
        close(unix)
        conn.close()
    }
}

// MARK: - VM

final class Helper: NSObject, VZVirtualMachineDelegate, VZVirtioSocketListenerDelegate {
    let config: Config
    let api: String
    var vm: VZVirtualMachine!
    var socketDevice: VZVirtioSocketDevice?
    var sources: [DispatchSourceSignal] = []

    init(config: Config, api: String) {
        self.config = config
        self.api = api
    }

    func configuration() throws -> VZVirtualMachineConfiguration {
        checkFile(config.kernel, "kernel")
        if let i = config.initramfs { checkFile(i, "initramfs") }
        for d in config.disks { checkFile(d.path, "disk") }

        let c = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: config.kernel))
        boot.commandLine = config.cmdline
        if let i = config.initramfs { boot.initialRamdiskURL = URL(fileURLWithPath: i) }
        c.bootLoader = boot
        c.platform = VZGenericPlatformConfiguration()
        c.cpuCount = config.vcpus
        c.memorySize = config.memory_mib * 1024 * 1024
        // In order: vda, vdb, ...
        c.storageDevices = try config.disks.map { d in
            let a = try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: d.path), readOnly: d.read_only)
            return VZVirtioBlockDeviceConfiguration(attachment: a)
        }
        // The console (hvc0) writes to stdout, which vmkit opened for appending.
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: nil, fileHandleForWriting: FileHandle.standardOutput)
        c.serialPorts = [console]
        c.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        if config.vsock != nil { c.socketDevices = [VZVirtioSocketDeviceConfiguration()] }
        // No network device: the guest has no NIC, so it has no egress at all.
        c.networkDevices = []
        try c.validate()
        return c
    }

    func run() {
        let c: VZVirtualMachineConfiguration
        do { c = try configuration() } catch { die("invalid configuration: \(error.localizedDescription)") }
        vm = VZVirtualMachine(configuration: c)
        vm.delegate = self
        if let v = config.vsock, let dev = vm.socketDevices.first as? VZVirtioSocketDevice {
            socketDevice = dev
            let listener = VZVirtioSocketListener()
            listener.delegate = self
            guard v.first_port <= v.last_port else { die("vsock: first_port > last_port") }
            for p in v.first_port...v.last_port { dev.setSocketListener(listener, forPort: p) }
            acceptLoop(unixListen(v.socket)) { self.hostConnection($0) }
        }
        installSignals()
        // Last: once the API socket accepts, vmkit treats the VM as created.
        acceptLoop(unixListen(api)) { self.apiConnection($0) }
    }

    // MARK: API

    func apiConnection(_ fd: Int32) {
        guard let line = readLine(fd),
              let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
              let op = obj["op"] as? String
        else {
            reply(fd, "malformed request")
            return
        }
        DispatchQueue.main.async {
            let done: (Result<Void, Error>) -> Void = { r in
                switch r {
                case .success: self.reply(fd, nil)
                case .failure(let e): self.reply(fd, "\(op): \(e.localizedDescription)")
                }
            }
            switch op {
            case "start": self.vm.start(completionHandler: done)
            case "pause": self.vm.pause(completionHandler: done)
            case "resume": self.vm.resume(completionHandler: done)
            default: self.reply(fd, "unknown op \(op)")
            }
        }
    }

    func reply(_ fd: Int32, _ error: String?) {
        var obj: [String: Any] = ["ok": error == nil]
        if let error { obj["error"] = error }
        var data = (try? JSONSerialization.data(withJSONObject: obj)) ?? Data("{\"ok\":false}".utf8)
        data.append(UInt8(ascii: "\n"))
        _ = writeAll(fd, [UInt8](data))
        close(fd)
    }

    // MARK: vsock

    // Host-initiated connections: "CONNECT <port>\n" in, "OK <n>\n" out, then bytes.
    func hostConnection(_ cfd: Int32) {
        guard let line = readLine(cfd, max: 64), line.hasPrefix("CONNECT "),
              let port = UInt32(line.dropFirst(8).trimmingCharacters(in: .whitespaces))
        else { close(cfd); return }
        DispatchQueue.main.async {
            guard let dev = self.socketDevice else { close(cfd); return }
            dev.connect(toPort: port) { r in
                switch r {
                case .success(let conn):
                    _ = writeAll(cfd, Array("OK \(conn.sourcePort)\n".utf8))
                    splice(unix: cfd, conn: conn)
                case .failure:
                    close(cfd)
                }
            }
        }
    }

    // Guest-initiated connections: relayed to "<socket>_<port>"; refused if nobody listens there.
    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection conn: VZVirtioSocketConnection,
                  from device: VZVirtioSocketDevice) -> Bool {
        guard let v = config.vsock, let fd = unixConnect("\(v.socket)_\(conn.destinationPort)") else { return false }
        splice(unix: fd, conn: conn)
        return true
    }

    // MARK: Lifecycle

    func installSignals() {
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            s.setEventHandler {
                // A hard stop: graceful shutdown goes through the guest.
                if self.vm.canStop { self.vm.stop { _ in exit(0) } } else { exit(0) }
            }
            s.resume()
            sources.append(s)
        }
    }

    func guestDidStop(_ vm: VZVirtualMachine) {
        exit(0)
    }

    func virtualMachine(_ vm: VZVirtualMachine, didStopWithError error: Error) {
        log("the VM stopped with an error: \(error.localizedDescription)")
        exit(1)
    }
}

// MARK: - Main

func main() {
    var args = CommandLine.arguments.dropFirst().makeIterator()
    var configPath: String?
    var api: String?
    while let a = args.next() {
        switch a {
        case "--version":
            print("vmkit-vz v\(version)")
            exit(0)
        case "--check":
            if VZVirtualMachine.isSupported { exit(0) }
            die("this Mac cannot run virtual machines (VZVirtualMachine.isSupported is false)", code: 3)
        case "--config": configPath = args.next()
        case "--api": api = args.next()
        default: die("unknown argument \(a)")
        }
    }
    guard let configPath, let api else { die("usage: vmkit-vz --config FILE --api SOCKET") }
    guard let data = FileManager.default.contents(atPath: configPath) else { die("cannot read \(configPath)") }
    let config: Config
    do { config = try JSONDecoder().decode(Config.self, from: data) } catch { die("\(configPath): \(error)") }
    signal(SIGPIPE, SIG_IGN)
    let helper = Helper(config: config, api: api)
    DispatchQueue.main.async { helper.run() }
    withExtendedLifetime(helper) { dispatchMain() }
}

main()
