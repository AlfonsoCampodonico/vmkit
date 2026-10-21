//! Rewriting a Cloud Hypervisor snapshot's `config.json` for restore (lazy-restore design
//! §4.5).
//!
//! On restore Cloud Hypervisor takes every path and device from `config.json`, and a bundle is
//! untrusted. So vmkit never passes the file on as it is: it builds a new one that keeps only
//! what the VMM needs to match `state.json` (CPU, memory and device shapes), refuses device
//! classes vmkit never creates (shared directories, PMEM, VFIO, vDPA, vhost-user, ...), and sets
//! every path, the console and the Landlock rules itself, exactly as `vm.create` does.

use serde_json::{Map, Value, json};

use crate::bundle::BundleInfo;
use crate::error::{Error, Result};
use crate::net;
use crate::sandbox;

fn bad(msg: impl Into<String>) -> Error {
    Error::Snapshot(format!("config.json: {}", msg.into()))
}

/// Whether `v` asks for nothing: absent, null, false, empty.
fn unset(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => true,
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// The entries of `obj` named in `keep`. Any other entry must be unset, and is dropped.
fn pick(what: &str, obj: &Value, keep: &[&str]) -> Result<Map<String, Value>> {
    let obj = obj.as_object().ok_or_else(|| bad(format!("{what} is not an object")))?;
    let mut out = Map::new();
    for (k, v) in obj {
        if keep.contains(&k.as_str()) {
            out.insert(k.clone(), v.clone());
        } else if !unset(v) {
            return Err(bad(format!("{what}.{k} is not something vmkit restores")));
        }
    }
    Ok(out)
}

/// Scalars only: a nested object could carry paths or devices.
fn scalars(what: &str, map: &Map<String, Value>) -> Result<()> {
    for (k, v) in map {
        if v.is_object() || v.is_array() {
            return Err(bad(format!("{what}.{k} must be a plain value")));
        }
    }
    Ok(())
}

fn require(what: &str, map: &Map<String, Value>, key: &str, want: &Value) -> Result<()> {
    match map.get(key) {
        Some(v) if v == want => Ok(()),
        other => Err(bad(format!("{what}.{key} is {other:?}, expected {want}"))),
    }
}

const CPUS: &[&str] = &[
    "boot_vcpus",
    "max_vcpus",
    "kvm_hyperv",
    "max_phys_bits",
    "features",
    "nested",
    "core_scheduling",
    "profile",
];
const MEMORY: &[&str] = &[
    "size",
    "mergeable",
    "hotplug_method",
    "hotplug_size",
    "hotplugged_size",
    "shared",
    "hugepages",
    "hugepage_size",
    "prefault",
    "reserve",
    "thp",
];
const DISK: &[&str] = &[
    "id",
    "pci_segment",
    "readonly",
    "direct",
    "num_queues",
    "queue_size",
    "disable_io_uring",
    "disable_aio",
    "sparse",
    "image_type",
    "lock_granularity",
    "iommu",
];
const NET: &[&str] = &[
    "id",
    "pci_segment",
    "mac",
    "mtu",
    "num_queues",
    "queue_size",
    "iommu",
    "offload_tso",
    "offload_ufo",
    "offload_csum",
];
const DEVICE: &[&str] = &["id", "pci_segment", "iommu"];
const PLATFORM: &[&str] = &["num_pci_segments", "iommu_address_width_bits"];
/// Top-level entries vmkit keeps or replaces. Any other must be unset.
const TOP: &[&str] = &[
    "cpus",
    "memory",
    "payload",
    "disks",
    "net",
    "rng",
    "serial",
    "console",
    "vsock",
    "pvpanic",
    "iommu",
    "watchdog",
    "platform",
    "landlock_enable",
    "landlock_rules",
    "debug_console",
];

/// The `config.json` to restore `snapshot` with: `info` is the checked bundle, and
/// `landlock` the rules for the restoring sandbox.
pub(crate) fn rewrite(snapshot: &Value, info: &BundleInfo, landlock: Vec<Value>) -> Result<Value> {
    let top = pick("config", snapshot, TOP)?;
    let get = |k: &str| top.get(k).cloned().unwrap_or(Value::Null);

    let mut cpus = pick("cpus", &get("cpus"), CPUS)?;
    require("cpus", &cpus, "boot_vcpus", &json!(info.vcpus))?;
    require("cpus", &cpus, "max_vcpus", &json!(info.vcpus))?;
    // `features` is an object of CPU feature flags; nothing in it names a file.
    let features = cpus.remove("features");
    scalars("cpus", &cpus)?;
    if let Some(f) = features {
        if !f
            .as_object()
            .is_some_and(|o| o.values().all(|v| !v.is_object() && !v.is_array()))
        {
            return Err(bad("cpus.features must be flags"));
        }
        cpus.insert("features".into(), f);
    }

    let memory = pick("memory", &get("memory"), MEMORY)?;
    scalars("memory", &memory)?;
    require("memory", &memory, "size", &json!(u64::from(info.memory_mib) << 20))?;
    for k in ["shared", "hugepages"] {
        if memory.get(k).is_some_and(|v| !unset(v)) {
            return Err(bad(format!("memory.{k} is not something vmkit restores")));
        }
    }

    let payload = pick("payload", &get("payload"), &["kernel", "initramfs", "cmdline"])?;
    let mut new_payload = json!({ "kernel": sandbox::KERNEL });
    match payload.get("cmdline") {
        Some(Value::String(c)) => new_payload["cmdline"] = json!(c),
        None | Some(Value::Null) => {}
        Some(_) => return Err(bad("payload.cmdline must be a string")),
    }
    if payload.get("initramfs").is_some_and(|v| !v.is_null()) {
        new_payload["initramfs"] = json!(sandbox::INITRAMFS);
    }

    let disks = get("disks");
    let disks = if disks.is_null() {
        Vec::new()
    } else {
        disks.as_array().cloned().ok_or_else(|| bad("disks is not a list"))?
    };
    if disks.len() != info.disks.len() {
        return Err(bad(format!(
            "{} disks, but the bundle has {}",
            disks.len(),
            info.disks.len()
        )));
    }
    let mut new_disks = Vec::new();
    for (n, (d, want)) in disks.iter().zip(&info.disks).enumerate() {
        let what = format!("disks[{n}]");
        let mut d = pick(&what, d, &[DISK, &["path", "vhost_user", "backing_files"]].concat())?;
        for k in ["vhost_user", "backing_files"] {
            if d.remove(k).is_some_and(|v| !unset(&v)) {
                return Err(bad(format!("{what}.{k} is not something vmkit restores")));
            }
        }
        d.remove("path");
        scalars(&what, &d)?;
        require(&what, &d, "readonly", &json!(want.read_only))?;
        if d.get("image_type").is_some_and(|t| t != "Raw") {
            return Err(bad(format!("{what} is not a raw image")));
        }
        d.insert("path".into(), json!(sandbox::disk(n)));
        d.insert("image_type".into(), json!("Raw"));
        new_disks.push(Value::Object(d));
    }

    let nets = get("net");
    let nets = if nets.is_null() {
        Vec::new()
    } else {
        nets.as_array().cloned().ok_or_else(|| bad("net is not a list"))?
    };
    if nets.len() != usize::from(info.net) {
        return Err(bad(format!(
            "{} NICs, but the bundle has {}",
            nets.len(),
            usize::from(info.net)
        )));
    }
    let mut new_nets = Vec::new();
    for (n, nic) in nets.iter().enumerate() {
        let what = format!("net[{n}]");
        // The tap's host-side address and the like are dropped: vmkit configures the tap.
        let mut nic = pick(
            &what,
            nic,
            &[NET, &["tap", "ip", "mask", "host_mac", "vhost_user", "vhost_mode"]].concat(),
        )?;
        if nic.remove("vhost_user").is_some_and(|v| !unset(&v)) {
            return Err(bad(format!("{what}.vhost_user is not something vmkit restores")));
        }
        for k in ["tap", "ip", "mask", "host_mac", "vhost_mode"] {
            nic.remove(k);
        }
        scalars(&what, &nic)?;
        nic.insert("tap".into(), json!(net::TAP));
        new_nets.push(Value::Object(nic));
    }

    let mut config = json!({
        "cpus": cpus,
        "memory": memory,
        "payload": new_payload,
        "disks": new_disks,
        "serial": {"mode": "Tty"},
        "landlock_enable": true,
        "landlock_rules": landlock,
    });
    if !new_nets.is_empty() {
        config["net"] = json!(new_nets);
    }
    let mut console = pick("console", &get("console"), &["mode", "pci_segment", "iommu"])?;
    console.insert("mode".into(), json!("Off"));
    scalars("console", &console)?;
    config["console"] = Value::Object(console);
    if !get("rng").is_null() {
        let mut rng = pick("rng", &get("rng"), &[DEVICE, &["src"]].concat())?;
        rng.insert("src".into(), json!("/dev/urandom"));
        scalars("rng", &rng)?;
        config["rng"] = Value::Object(rng);
    }
    match (get("vsock"), info.vsock) {
        (Value::Null, None) => {}
        (v, Some(want)) if !v.is_null() => {
            let mut v = pick("vsock", &v, &[DEVICE, &["cid", "socket"]].concat())?;
            require("vsock", &v, "cid", &json!(want.guest_cid))?;
            v.insert("socket".into(), json!(sandbox::inside("vsock.sock")));
            scalars("vsock", &v)?;
            config["vsock"] = Value::Object(v);
        }
        _ => return Err(bad("the vsock device does not match the bundle")),
    }
    for k in ["pvpanic", "iommu", "watchdog"] {
        match get(k) {
            Value::Null => {}
            Value::Bool(b) => config[k] = json!(b),
            _ => return Err(bad(format!("{k} must be a boolean"))),
        }
    }
    // Cloud Hypervisor x86_64 always records its debug port, off unless asked for.
    if !get("debug_console").is_null() {
        let mut d = pick("debug_console", &get("debug_console"), &["mode", "file", "iobase"])?;
        if d.remove("file").is_some_and(|f| !f.is_null()) {
            return Err(bad("debug_console.file is not something vmkit restores"));
        }
        d.insert("mode".into(), json!("Off"));
        scalars("debug_console", &d)?;
        config["debug_console"] = Value::Object(d);
    }
    if !get("platform").is_null() {
        let p = pick("platform", &get("platform"), PLATFORM)?;
        scalars("platform", &p)?;
        config["platform"] = Value::Object(p);
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleVsock, DiskInfo, VmmId};

    /// A Cloud Hypervisor 53 snapshot's `config.json` (aarch64, one disk, vsock), as written
    /// for a VM vmkit created.
    const CH53: &str = include_str!("../tests/data/ch53-config.json");

    fn info() -> BundleInfo {
        BundleInfo {
            version: 1,
            vmm: VmmId {
                name: "cloud-hypervisor".into(),
                version: "53.0.0".into(),
            },
            arch: "aarch64".into(),
            vcpus: 1,
            memory_mib: 256,
            net: false,
            vsock: Some(BundleVsock { guest_cid: 3 }),
            disks: vec![DiskInfo {
                read_only: false,
                size: 64 << 20,
                captured: true,
            }],
            files: Vec::new(),
        }
    }

    fn snapshot() -> Value {
        serde_json::from_str(CH53).unwrap()
    }

    fn rules() -> Vec<Value> {
        vec![json!({"path": "/vm/sock", "access": "rw"})]
    }

    fn refused(v: &Value) -> String {
        match rewrite(v, &info(), rules()) {
            Err(Error::Snapshot(m)) => m,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_keeps_the_shapes_and_fixes_every_path() {
        let c = rewrite(&snapshot(), &info(), rules()).unwrap();
        assert_eq!(c["payload"]["kernel"], "/vm/kernel");
        assert_eq!(c["payload"]["initramfs"], "/vm/initramfs");
        assert_eq!(c["payload"]["cmdline"], snapshot()["payload"]["cmdline"]);
        assert_eq!(c["disks"][0]["path"], "/vm/disk/0");
        assert_eq!(c["disks"][0]["id"], "_disk0");
        assert_eq!(c["disks"][0]["image_type"], "Raw");
        assert_eq!(c["vsock"]["socket"], "/vm/sock/vsock.sock");
        assert_eq!(c["vsock"]["id"], "_vsock1");
        assert_eq!(c["cpus"], snapshot()["cpus"]);
        assert_eq!(c["memory"], snapshot()["memory"]);
        assert_eq!(c["serial"], json!({"mode": "Tty"}));
        assert_eq!(c["console"]["mode"], "Off");
        assert_eq!(c["landlock_enable"], true);
        assert_eq!(c["landlock_rules"], json!(rules()));
        assert!(
            !c.to_string().contains("/tmp/") && !c.to_string().contains("/Users/"),
            "no host path survives: {c}"
        );
    }

    #[test]
    fn rewrite_refuses_device_classes_vmkit_never_creates() {
        for (key, value) in [
            ("fs", json!([{"tag": "x", "socket": "/tmp/virtiofsd.sock"}])),
            ("pmem", json!([{"file": "/etc/shadow"}])),
            ("devices", json!([{"path": "/sys/bus/pci/devices/0000:00:01.0"}])),
            ("user_devices", json!([{"socket": "/tmp/u.sock"}])),
            ("vdpa", json!([{"path": "/dev/vhost-vdpa-0"}])),
            ("balloon", json!({"size": 0})),
            ("numa", json!([{"guest_numa_id": 0}])),
            ("tpm", json!({"socket": "/tmp/swtpm"})),
        ] {
            let mut v = snapshot();
            v[key] = value;
            assert!(refused(&v).contains(key), "{key}");
        }
    }

    #[test]
    fn rewrite_refuses_vhost_user_and_backing_files_and_odd_memory() {
        let mut v = snapshot();
        v["disks"][0]["vhost_user"] = json!(true);
        assert!(refused(&v).contains("vhost_user"));
        let mut v = snapshot();
        v["disks"][0]["vhost_socket"] = json!("/tmp/vu.sock");
        assert!(refused(&v).contains("vhost_socket"));
        let mut v = snapshot();
        v["disks"][0]["backing_files"] = json!(true);
        assert!(refused(&v).contains("backing_files"));
        let mut v = snapshot();
        v["memory"]["zones"] = json!([{"file": "/dev/mem"}]);
        assert!(refused(&v).contains("zones"));
        let mut v = snapshot();
        v["memory"]["shared"] = json!(true);
        assert!(refused(&v).contains("shared"));
        let mut v = snapshot();
        v["memory"]["size"] = json!(1u64 << 40);
        assert!(refused(&v).contains("size"));
    }

    #[test]
    fn rewrite_refuses_shapes_that_disagree_with_the_bundle() {
        let mut v = snapshot();
        v["disks"] = json!([]);
        assert!(refused(&v).contains("disks"));
        let mut v = snapshot();
        v["disks"][0]["readonly"] = json!(true);
        assert!(refused(&v).contains("readonly"));
        let mut v = snapshot();
        v["cpus"]["boot_vcpus"] = json!(8);
        assert!(refused(&v).contains("boot_vcpus"));
        let mut v = snapshot();
        v["vsock"]["cid"] = json!(4);
        assert!(refused(&v).contains("cid"));
        let mut v = snapshot();
        v["net"] = json!([{"tap": "eth0", "mac": "12:34:56:78:90:ab"}]);
        assert!(refused(&v).contains("NIC"));
    }

    #[test]
    fn the_x86_64_debug_console_is_kept_off() {
        let mut v = snapshot();
        v["debug_console"] = json!({"file": null, "mode": "Off", "iobase": 233});
        let c = rewrite(&v, &info(), rules()).unwrap();
        assert_eq!(c["debug_console"], json!({"mode": "Off", "iobase": 233}));
        v["debug_console"] = json!({"file": "/etc/passwd", "mode": "File", "iobase": 233});
        assert!(refused(&v).contains("debug_console.file"));
    }

    #[test]
    fn rewrite_names_the_vmkit_tap() {
        let mut v = snapshot();
        v["net"] = json!([{"id": "_net2", "tap": "evil0", "ip": "10.0.0.1", "mask": "255.0.0.0", "mac": "12:34:56:78:90:ab", "vhost_user": false}]);
        let mut i = info();
        i.net = true;
        let c = rewrite(&v, &i, rules()).unwrap();
        assert_eq!(
            c["net"],
            json!([{"id": "_net2", "tap": "tap0", "mac": "12:34:56:78:90:ab"}])
        );
    }
}
