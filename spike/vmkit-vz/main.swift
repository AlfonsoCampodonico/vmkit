// vmkit-vz: a throwaway spike helper that boots a Linux guest on Apple's
// Virtualization.framework (see docs/spikes/apple-vz.md). Not wired into vmkit.
//
//   vmkit-vz --kernel K --cmdline "..." [--initrd I] [--disk PATH[:ro]]...
//            [--cpus N] [--memory-mib M] --console-log FILE
//            [--vsock-uds PATH --vsock-listen 1024-1029,...]
//            [--save-on-usr1 FILE] [--restore FILE]
//
// vsock is bridged the way Firecracker's hybrid vsock is:
//   host-initiated:  connect to PATH, send "CONNECT <port>\n", read "OK <n>\n", then bytes
//   guest-initiated: the helper connects to PATH_<port> (the host listens there)
// VZ has no wildcard listener, so guest-initiated ports are listed up front.
//
// Experiment knobs (environment): VZ_NO_CONSOLE, VZ_NO_ENTROPY drop those devices;
// VZ_MACHINE_ID=<file> persists the generic machine identifier for save/restore.

import Darwin
import Foundation
import Virtualization

// MARK: - Arguments

struct Options {
    var kernel = ""
    var initrd: String?
    var cmdline = ""
    var disks: [(String, Bool)] = []
    var cpus = 1
    var memoryMiB: UInt64 = 512
    var consoleLog = ""
    var vsockUDS: String?
    var listenPorts: [UInt32] = []
    var saveOnUSR1: String?
    var restore: String?
}

func die(_ msg: String) -> Never {
    FileHandle.standardError.write("vmkit-vz: \(msg)\n".data(using: .utf8)!)
    exit(2)
}

func need<T>(_ v: T?, _ msg: @autoclosure () -> String) -> T {
    guard let v else { die(msg()) }
    return v
}

func parsePorts(_ s: String) -> [UInt32] {
    s.split(separator: ",").flatMap { part -> [UInt32] in
        let r = part.split(separator: "-").map { need(UInt32($0), "bad port \(part)") }
        return r.count == 2 ? Array(r[0]...r[1]) : [r[0]]
    }
}

func parse() -> Options {
    var o = Options()
    var it = CommandLine.arguments.dropFirst().makeIterator()
    func next(_ flag: String) -> String { need(it.next(), "\(flag) needs a value") }
    while let a = it.next() {
        switch a {
        case "--kernel": o.kernel = next(a)
        case "--initrd": o.initrd = next(a)
        case "--cmdline": o.cmdline = next(a)
        case "--disk":
            let v = next(a)
            if v.hasSuffix(":ro") { o.disks.append((String(v.dropLast(3)), true)) } else { o.disks.append((v, false)) }
        case "--cpus": o.cpus = need(Int(next(a)), "bad --cpus")
        case "--memory-mib": o.memoryMiB = need(UInt64(next(a)), "bad --memory-mib")
        case "--console-log": o.consoleLog = next(a)
        case "--vsock-uds": o.vsockUDS = next(a)
        case "--vsock-listen": o.listenPorts = parsePorts(next(a))
        case "--save-on-usr1": o.saveOnUSR1 = next(a)
        case "--restore": o.restore = next(a)
        default: die("unknown argument \(a)")
        }
    }
    if o.kernel.isEmpty || o.consoleLog.isEmpty { die("--kernel and --console-log are required") }
    return o
}

let t0 = Date()
func log(_ msg: String) {
    let ms = String(format: "%8.1f", Date().timeIntervalSince(t0) * 1000)
    FileHandle.standardError.write("[\(ms) ms] \(msg)\n".data(using: .utf8)!)
}

// MARK: - Unix sockets

func unixAddr(_ path: String) -> sockaddr_un {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8)
    precondition(bytes.count < MemoryLayout.size(ofValue: addr.sun_path), "socket path too long: \(path)")
    withUnsafeMutableBytes(of: &addr.sun_path) { buf in
        for (i, b) in bytes.enumerated() { buf[i] = b }
    }
    return addr
}

func unixConnect(_ path: String) -> Int32? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    var addr = unixAddr(path)
    let rc = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    if rc != 0 { close(fd); return nil }
    return fd
}

func unixListen(_ path: String) -> Int32 {
    unlink(path)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    var addr = unixAddr(path)
    let rc = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    if rc != 0 || listen(fd, 64) != 0 { die("listen on \(path): \(String(cString: strerror(errno)))") }
    return fd
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
func readLine(_ fd: Int32, max: Int = 64) -> String? {
    var line: [UInt8] = []
    var b: UInt8 = 0
    while line.count < max {
        let n = read(fd, &b, 1)
        if n <= 0 { return nil }
        if b == UInt8(ascii: "\n") { return String(decoding: line, as: UTF8.self) }
        line.append(b)
    }
    return nil
}

// MARK: - Byte relay

/// Copies bytes both ways between a unix socket and a vsock connection until
/// both directions reach EOF, propagating half-close. Holds the connection
/// (its descriptor is the connection's) until done.
func splice(unix: Int32, conn: VZVirtioSocketConnection, label: String) {
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
        log("vsock \(label): closed")
    }
}

// MARK: - VM

final class Helper: NSObject, VZVirtualMachineDelegate, VZVirtioSocketListenerDelegate {
    let opts: Options
    var vm: VZVirtualMachine!
    var socketDevice: VZVirtioSocketDevice?

    init(_ opts: Options) { self.opts = opts }

    func configuration() throws -> VZVirtualMachineConfiguration {
        let c = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: opts.kernel))
        boot.commandLine = opts.cmdline
        if let i = opts.initrd { boot.initialRamdiskURL = URL(fileURLWithPath: i) }
        c.bootLoader = boot
        c.cpuCount = opts.cpus
        c.memorySize = opts.memoryMiB * 1024 * 1024
        let platform = VZGenericPlatformConfiguration()
        // Save/restore needs the same machine identifier on both sides.
        if let path = ProcessInfo.processInfo.environment["VZ_MACHINE_ID"] {
            if let d = FileManager.default.contents(atPath: path),
               let id = VZGenericMachineIdentifier(dataRepresentation: d) {
                platform.machineIdentifier = id
            } else {
                FileManager.default.createFile(atPath: path, contents: platform.machineIdentifier.dataRepresentation)
            }
        }
        c.platform = platform

        c.storageDevices = try opts.disks.map { path, ro in
            let a = try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: path), readOnly: ro)
            return VZVirtioBlockDeviceConfiguration(attachment: a)
        }

        if !opts.consoleLog.isEmpty && ProcessInfo.processInfo.environment["VZ_NO_CONSOLE"] == nil {
            FileManager.default.createFile(atPath: opts.consoleLog, contents: nil)
            let logHandle = try FileHandle(forWritingTo: URL(fileURLWithPath: opts.consoleLog))
            let console = VZVirtioConsoleDeviceSerialPortConfiguration()
            console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: logHandle)
            c.serialPorts = [console]
        }

        if opts.vsockUDS != nil { c.socketDevices = [VZVirtioSocketDeviceConfiguration()] }
        if ProcessInfo.processInfo.environment["VZ_NO_ENTROPY"] == nil {
            c.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        }
        // No network device: the guest has no NIC at all.
        c.networkDevices = []

        try c.validate()
        if opts.saveOnUSR1 != nil || opts.restore != nil { try c.validateSaveRestoreSupport() }
        return c
    }

    func run() throws {
        vm = VZVirtualMachine(configuration: try configuration())
        vm.delegate = self
        stateObs = vm.observe(\.state, options: [.new]) { vm, _ in log("state -> \(vm.state.rawValue)") }
        socketDevice = vm.socketDevices.first as? VZVirtioSocketDevice
        if let dev = socketDevice {
            let listener = VZVirtioSocketListener()
            listener.delegate = self
            for p in opts.listenPorts { dev.setSocketListener(listener, forPort: p) }
            if let uds = opts.vsockUDS { startHostListener(uds) }
        }
        if let state = opts.restore {
            log("restoring from \(state)")
            vm.restoreMachineStateFrom(url: URL(fileURLWithPath: state)) { err in
                if let err { die("restore: \(err)") }
                log("restored; resuming")
                self.vm.resume { r in
                    if case .failure(let e) = r { die("resume: \(e)") }
                    log("resumed")
                }
            }
        } else {
            log("starting")
            vm.start { r in
                switch r {
                case .success: log("started")
                case .failure(let e): die("start: \(e)")
                }
            }
        }
        installSignals()
    }

    // Host-initiated connections: a unix listener, "CONNECT <port>\n" in, "OK <n>\n" out.
    func startHostListener(_ path: String) {
        let lfd = unixListen(path)
        Thread.detachNewThread {
            while true {
                let cfd = accept(lfd, nil, nil)
                if cfd < 0 { if errno == EINTR { continue }; break }
                Thread.detachNewThread { self.handleHostConnection(cfd) }
            }
        }
    }

    func handleHostConnection(_ cfd: Int32) {
        guard let line = readLine(cfd), line.hasPrefix("CONNECT "),
              let port = UInt32(line.dropFirst(8).trimmingCharacters(in: .whitespaces))
        else { close(cfd); return }
        DispatchQueue.main.async {
            guard let dev = self.socketDevice else { close(cfd); return }
            dev.connect(toPort: port) { r in
                switch r {
                case .success(let conn):
                    log("vsock host->guest port \(port): connected")
                    _ = writeAll(cfd, Array("OK \(conn.sourcePort)\n".utf8))
                    splice(unix: cfd, conn: conn, label: "host->guest:\(port)")
                case .failure(let e):
                    log("vsock host->guest port \(port): \(e.localizedDescription)")
                    close(cfd)
                }
            }
        }
    }

    // Guest-initiated connections: relay to "<uds>_<port>".
    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection conn: VZVirtioSocketConnection,
                  from device: VZVirtioSocketDevice) -> Bool {
        guard let uds = opts.vsockUDS else { return false }
        let port = conn.destinationPort
        guard let fd = unixConnect("\(uds)_\(port)") else {
            log("vsock guest->host port \(port): nobody listens on \(uds)_\(port); refused")
            return false
        }
        log("vsock guest->host port \(port): accepted (guest port \(conn.sourcePort))")
        splice(unix: fd, conn: conn, label: "guest->host:\(port)")
        return true
    }

    func installSignals() {
        func on(_ sig: Int32, _ f: @escaping () -> Void) {
            signal(sig, SIG_IGN)
            let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            s.setEventHandler(handler: f)
            s.resume()
            sources.append(s)
        }
        on(SIGTERM) { log("SIGTERM: stopping"); self.vm.stop { _ in exit(0) } }
        on(SIGINT) { log("SIGINT: stopping"); self.vm.stop { _ in exit(0) } }
        if let path = opts.saveOnUSR1 {
            on(SIGUSR1) {
                log("SIGUSR1: pausing")
                self.vm.pause { r in
                    if case .failure(let e) = r { die("pause: \(e)") }
                    let t = Date()
                    self.vm.saveMachineStateTo(url: URL(fileURLWithPath: path)) { err in
                        if let err { die("save: \(err)") }
                        log(String(format: "saved to %@ in %.1f ms; stopping", path, Date().timeIntervalSince(t) * 1000))
                        self.vm.stop { _ in exit(0) }
                    }
                }
            }
        }
    }
    var sources: [DispatchSourceSignal] = []
    var stateObs: NSKeyValueObservation?

    func guestDidStop(_ vm: VZVirtualMachine) {
        log("guest stopped the VM")
        exit(0)
    }

    func virtualMachine(_ vm: VZVirtualMachine, didStopWithError error: Error) {
        log("VM stopped with error: \(error)")
        exit(1)
    }
}

signal(SIGPIPE, SIG_IGN)
let helper = Helper(parse())
DispatchQueue.main.async {
    do { try helper.run() } catch { die("\(error)") }
}
dispatchMain()
