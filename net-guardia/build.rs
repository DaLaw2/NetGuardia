use std::{
    env, fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};
use std::time::SystemTime;
use cargo_metadata::{Artifact, CompilerMessage, Message, Metadata, MetadataCommand, Package, Target, TargetKind};

fn main() {
    build_ingress_ebpf();
    build_egress_ebpf();
    build_frontend();
}

/// This crate has a runtime dependency on artifacts produced by the `net-guardia-ingress-ebpf` crate.
/// This would be better expressed as one or more [artifact-dependencies][bindeps] but issues such
/// as:
///
/// * https://github.com/rust-lang/cargo/issues/12374
/// * https://github.com/rust-lang/cargo/issues/12375
/// * https://github.com/rust-lang/cargo/issues/12385
///
/// prevent their use for the time being.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn build_ingress_ebpf() {
    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let ebpf_package = packages
        .into_iter()
        .find(|Package { name, .. }| **name == "net-guardia-ingress-ebpf")
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

    // TODO(https://github.com/rust-lang/cargo/issues/4001): Make this `false` if we can determine
    // we're in a check build.
    let build_ebpf = true;
    if build_ebpf {
        let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();

        let target = format!("{target}-unknown-none");

        let Package { manifest_path, .. } = ebpf_package;
        let ebpf_dir = manifest_path.parent().unwrap();

        // We have a build-dependency on `net-guardia-ingress-ebpf`, so cargo will automatically rebuild us
        // if `net-guardia-ingress-ebpf`'s *library* target or any of its dependencies change. Since we
        // depend on `net-guardia-ingress-ebpf`'s *binary* targets, that only gets us half of the way. This
        // stanza ensures cargo will rebuild us on changes to the binaries too, which gets us the
        // rest of the way.
        println!("cargo:rerun-if-changed={}", ebpf_dir.as_str());

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

        // Workaround to make sure that the rust-toolchain.toml is respected.
        for key in ["RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }
        cmd.current_dir(ebpf_dir);

        // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
        let ebpf_target_dir = out_dir.join("net-guardia-ingress-ebpf");
        cmd.arg("--target-dir").arg(&ebpf_target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
        let Child { stdout, stderr, .. } = &mut child;

        // Trampoline stdout to cargo warnings.
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

/// This crate has a runtime dependency on artifacts produced by the `net-guardia-egress-ebpf` crate.
/// This would be better expressed as one or more [artifact-dependencies][bindeps] but issues such
/// as:
///
/// * https://github.com/rust-lang/cargo/issues/12374
/// * https://github.com/rust-lang/cargo/issues/12375
/// * https://github.com/rust-lang/cargo/issues/12385
///
/// prevent their use for the time being.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn build_egress_ebpf() {
    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let ebpf_package = packages
        .into_iter()
        .find(|Package { name, .. }| **name == "net-guardia-egress-ebpf")
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

    // TODO(https://github.com/rust-lang/cargo/issues/4001): Make this `false` if we can determine
    // we're in a check build.
    let build_ebpf = true;
    if build_ebpf {
        let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();

        let target = format!("{target}-unknown-none");

        let Package { manifest_path, .. } = ebpf_package;
        let ebpf_dir = manifest_path.parent().unwrap();

        // We have a build-dependency on `net-guardia-egress-ebpf`, so cargo will automatically rebuild us
        // if `net-guardia-egress-ebpf`'s *library* target or any of its dependencies change. Since we
        // depend on `net-guardia-egress-ebpf`'s *binary* targets, that only gets us half of the way. This
        // stanza ensures cargo will rebuild us on changes to the binaries too, which gets us the
        // rest of the way.
        println!("cargo:rerun-if-changed={}", ebpf_dir.as_str());

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
        cmd.env("CARGO_TERM_COLOR", "always");

        // Workaround to make sure that the rust-toolchain.toml is respected.
        for key in ["RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }
        cmd.current_dir(ebpf_dir);

        // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
        let ebpf_target_dir = out_dir.join("net-guardia-egress-ebpf");
        cmd.arg("--target-dir").arg(&ebpf_target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
        let Child { stdout, stderr, .. } = &mut child;

        // Trampoline stdout to cargo warnings.
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

    let Some(frontend_dir) = env::var_os("FRONTEND_DIR") else {
        panic!("FRONTEND_DIR environment variable is required but not set");
    };

    let project_root = env::var("CARGO_MANIFEST_DIR").unwrap();
    let static_dir = PathBuf::from(project_root).join("static").join("web");
    let frontend_dir = PathBuf::from(frontend_dir);

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

    let mut cmd = Command::new("npm");
    cmd.arg("install").current_dir(&frontend_dir);

    let status = cmd
        .status()
        .unwrap_or_else(|err| panic!("failed to run npm install: {err}"));
    if !status.success() {
        panic!("npm install failed with exit code: {:?}", status.code());
    }

    let mut cmd = Command::new("npx");
    cmd.args(["next", "build"]).current_dir(&frontend_dir);

    let status = cmd
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

fn needs_frontend_rebuild(frontend_dir: &PathBuf, out_dir: &PathBuf, static_dir: &PathBuf) -> bool {
    if !out_dir.exists() {
        return true;
    }

    if !static_dir.exists() {
        return true;
    }

    let out_modified = match fs::metadata(out_dir).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => {
            return true;
        }
    };

    let static_modified = match fs::metadata(static_dir).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => {
            return true;
        }
    };

    let essential_items = [
        "src",
        "public",
        "package.json",
        "next.config.js",
        "tailwind.config.js",
        "postcss.config.js",
        "tsconfig.json",
        "package-lock.json",
    ];

    for item_name in essential_items {
        let item_path = frontend_dir.join(item_name);
        if !item_path.exists() {
            continue;
        }

        let item_modified = match get_dir_last_modified(&item_path) {
            Some(time) => time,
            None => continue,
        };

        if item_modified > out_modified {
            return true;
        }
    }

    if out_modified > static_modified {
        return true;
    }

    false
}

fn get_dir_last_modified(path: &PathBuf) -> Option<SystemTime> {
    if path.is_file() {
        return fs::metadata(path).and_then(|m| m.modified()).ok();
    }

    if path.is_dir() {
        let mut latest = fs::metadata(path).and_then(|m| m.modified()).ok()?;

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Some(modified) = get_dir_last_modified(&entry.path()) {
                    if modified > latest {
                        latest = modified;
                    }
                }
            }
        }

        return Some(latest);
    }

    None
}

fn copy_dir_all(src: &PathBuf, dst: &PathBuf) -> std::io::Result<()> {
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
