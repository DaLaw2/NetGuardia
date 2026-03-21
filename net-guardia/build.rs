use std::env;
use std::fs;
use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::SystemTime;

use cargo_metadata::{Artifact, CompilerMessage, Message, Metadata, MetadataCommand, Package, Target, TargetKind};

fn main() {
    build_ebpf_package("ingress-ebpf", "ingress-ebpf");
    build_ebpf_package("egress-ebpf", "egress-ebpf");
    build_frontend();
    embed_license_public_key();
}

fn embed_license_public_key() {
    let license_enabled = env::var("CARGO_FEATURE_LICENSE").is_ok();

    let project_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let key_path = project_root.join("license_pub.key");

    println!("cargo:rerun-if-changed={}", key_path.display());

    if key_path.exists() {
        let key_hex = fs::read_to_string(&key_path)
            .expect("Failed to read license_pub.key")
            .trim()
            .to_string();
        println!("cargo:rustc-env=LICENSE_PUBLIC_KEY={}", key_hex);
    } else if license_enabled {
        panic!(
            "license feature enabled but license_pub.key not found at {}.\n\
             Generate it with: cd license-generator && cargo run -- keygen\n\
             Then copy license_pub.key to the repo root.",
            key_path.display()
        );
    } else {
        println!("cargo:rustc-env=LICENSE_PUBLIC_KEY=DISABLED");
    }
}

/// Resolve the absolute path of bpf-linker.
/// Searches PATH first, then falls back to CARGO_HOME/bin.
fn find_bpf_linker() -> PathBuf {
    // Try PATH via which
    if let Ok(path) = which::which("bpf-linker") {
        return path;
    }

    // Fallback: CARGO_HOME/bin (handles CI cache + which v8 issues)
    let cargo_home = env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = env::var("HOME").unwrap_or_default();
        format!("{home}/.cargo")
    });
    let candidate = PathBuf::from(format!("{cargo_home}/bin/bpf-linker"));
    if candidate.exists() {
        return candidate;
    }

    panic!(
        "bpf-linker not found in PATH or $CARGO_HOME/bin.\n\
         Install with: cargo install bpf-linker"
    );
}

fn build_ebpf_package(package_name: &str, target_subdir: &str) {
    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let ebpf_package = packages
        .into_iter()
        .find(|Package { name, .. }| **name == *package_name)
        .unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        panic!("unsupported endian={:?}", endian)
    };

    let build_ebpf = true;
    if build_ebpf {
        let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();
        let target = format!("{target}-unknown-none");

        // Find bpf-linker once, pass its path to the subprocess explicitly.
        let bpf_linker = find_bpf_linker();
        let bpf_linker_str = bpf_linker.to_str()
            .expect("bpf-linker path is not valid UTF-8");

        let Package { manifest_path, .. } = ebpf_package;
        let ebpf_dir = manifest_path.parent().unwrap();

        println!("cargo:rerun-if-changed={}", ebpf_dir.as_str());
        println!("cargo:rerun-if-changed=../common/src");

        let mut cmd = Command::new("cargo");
        cmd.args([
            "build",
            "-Z",
            "build-std=core",
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target,
        ]);

        cmd.env("CARGO_CFG_BPF_TARGET_ARCH", arch);

        // Tell cargo which linker to use for the BPF targets.
        // This avoids relying on PATH in the subprocess.
        let linker_env_bpfel = "CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER";
        let linker_env_bpfeb = "CARGO_TARGET_BPFEB_UNKNOWN_NONE_LINKER";
        cmd.env(linker_env_bpfel, bpf_linker_str);
        cmd.env(linker_env_bpfeb, bpf_linker_str);

        for key in ["RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }
        cmd.current_dir(ebpf_dir);

        let ebpf_target_dir = out_dir.join(format!("../{target_subdir}"));
        cmd.arg("--target-dir").arg(&ebpf_target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
        let Child { stdout, stderr, .. } = &mut child;

        let stderr = stderr.take().unwrap();
        let stderr = BufReader::new(stderr);
        let stderr = std::thread::spawn(move || {
            for line in stderr.lines() {
                let line = line.unwrap();
                println!("{line}");
            }
        });

        let stdout = stdout.take().unwrap();
        let stdout = BufReader::new(stdout);
        let mut executables = Vec::new();
        for message in Message::parse_stream(stdout) {
            #[allow(clippy::collapsible_match)]
            match message.expect("valid JSON") {
                Message::CompilerArtifact(Artifact {
                    executable,
                    target: Target { name, .. },
                    ..
                }) => {
                    if let Some(executable) = executable {
                        executables.push((name, executable.into_std_path_buf()));
                    }
                }
                Message::CompilerMessage(CompilerMessage { message, .. }) => {
                    for line in message.rendered.unwrap_or_default().split('\n') {
                        println!("{line}");
                    }
                }
                Message::TextLine(line) => {
                    println!("{line}");
                }
                _ => {}
            }
        }

        let status = child
            .wait()
            .unwrap_or_else(|err| panic!("failed to wait for {cmd:?}: {err}"));
        assert_eq!(status.code(), Some(0), "{cmd:?} failed: {status:?}");

        stderr.join().map_err(std::panic::resume_unwind).unwrap();

        for (name, binary) in executables {
            let dst = out_dir.join(name);
            let _: u64 =
                fs::copy(&binary, &dst).unwrap_or_else(|err| panic!("failed to copy {binary:?} to {dst:?}: {err}"));
        }
    } else {
        let Package { targets, .. } = ebpf_package;
        for Target { name, kind, .. } in targets {
            if *kind != [TargetKind::Bin] {
                continue;
            }
            let dst = out_dir.join(name);
            fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
        }
    }
}

fn build_frontend() {
    let _ = dotenvy::dotenv();

    let project_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let static_dir = project_root.join("static").join("web");

    let project_name = project_root.file_name().unwrap().to_string_lossy();
    let frontend_dir = project_root
        .parent()
        .unwrap()
        .join(format!("{}-frontend", project_name));

    if !frontend_dir.exists() {
        panic!("Frontend directory {:?} does not exist", frontend_dir);
    }

    println!("cargo:rerun-if-changed={}", frontend_dir.join("src").display());
    println!("cargo:rerun-if-changed={}", frontend_dir.join("public").display());
    println!("cargo:rerun-if-changed={}", frontend_dir.join("package.json").display());
    println!("cargo:rerun-if-changed={}", frontend_dir.join("package-lock.json").display());
    println!("cargo:rerun-if-changed={}", frontend_dir.join("next.config.js").display());
    println!("cargo:rerun-if-changed={}", frontend_dir.join("tailwind.config.js").display());
    println!("cargo:rerun-if-changed={}", frontend_dir.join("postcss.config.js").display());
    println!("cargo:rerun-if-changed={}", frontend_dir.join("tsconfig.json").display());

    let out_dir = frontend_dir.join("out");
    let need_build = needs_frontend_rebuild(&frontend_dir, &out_dir, &static_dir);
    if !need_build {
        return;
    }

    let npm = which::which("npm")
        .unwrap_or_else(|_| panic!("npm not found in PATH. Install Node.js first."));

    let status = Command::new(&npm)
        .arg("install")
        .current_dir(&frontend_dir)
        .status()
        .unwrap_or_else(|err| panic!("failed to run npm install: {err}"));
    if !status.success() {
        panic!("npm install failed with exit code: {:?}", status.code());
    }

    let npx = which::which("npx")
        .unwrap_or_else(|_| panic!("npx not found in PATH. Install Node.js first."));

    let status = Command::new(&npx)
        .args(["next", "build"])
        .current_dir(&frontend_dir)
        .status()
        .unwrap_or_else(|err| panic!("failed to run next build: {err}"));
    if !status.success() {
        panic!("next build failed with exit code: {:?}", status.code());
    }

    if static_dir.exists() {
        fs::remove_dir_all(&static_dir).unwrap_or_else(|err| panic!("failed to remove {:?}: {err}", static_dir));
    }
    fs::create_dir_all(&static_dir).unwrap_or_else(|err| panic!("failed to create {:?}: {err}", static_dir));

    copy_dir_all(&out_dir, &static_dir).unwrap_or_else(|err| panic!("failed to copy frontend build: {err}"));
}

fn needs_frontend_rebuild(frontend_dir: &std::path::Path, out_dir: &std::path::Path, static_dir: &std::path::Path) -> bool {
    if !out_dir.exists() || !static_dir.exists() {
        return true;
    }

    let out_modified = match fs::metadata(out_dir).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => return true,
    };

    let static_modified = match fs::metadata(static_dir).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => return true,
    };

    let essential_items = [
        "src", "public", "package.json", "next.config.js",
        "tailwind.config.js", "postcss.config.js", "tsconfig.json", "package-lock.json",
    ];

    for item_name in essential_items {
        let item_path = frontend_dir.join(item_name);
        if !item_path.exists() {
            continue;
        }
        if let Some(item_modified) = get_dir_last_modified(&item_path)
            && item_modified > out_modified
        {
            return true;
        }
    }

    out_modified > static_modified
}

fn get_dir_last_modified(path: &std::path::Path) -> Option<SystemTime> {
    if path.is_file() {
        return fs::metadata(path).and_then(|m| m.modified()).ok();
    }

    if path.is_dir() {
        let mut latest = fs::metadata(path).and_then(|m| m.modified()).ok()?;
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Some(modified) = get_dir_last_modified(&entry.path())
                    && modified > latest
                {
                    latest = modified;
                }
            }
        }
        return Some(latest);
    }

    None
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
