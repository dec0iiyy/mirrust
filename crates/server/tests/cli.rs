//! The `mirrust` binary's command line, run as a process.

use std::process::{Command, Output};

fn mirrust(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mirrust"))
        .args(args)
        .output()
        .expect("run mirrust")
}

#[test]
fn version_prints_the_package_version_and_exits_zero() {
    for flag in ["--version", "-V"] {
        let output = mirrust(&[flag]);
        assert!(output.status.success(), "{flag}: {:?}", output.status);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("mirrust {}\n", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
        assert!(output.stderr.is_empty(), "{flag}");
    }
}

#[test]
fn the_usage_lists_the_version_flag() {
    let output = mirrust(&["--help"]);
    assert!(output.status.success());
    let usage = String::from_utf8_lossy(&output.stdout);
    assert!(usage.contains("-V, --version"), "{usage}");
}

// Only `--dry-run` and flag errors are run here, never a real install: a test run as root
// on a machine with systemd must not change that machine.

#[test]
fn install_dry_run_prints_the_steps_and_the_unit() {
    let output = mirrust(&[
        "install",
        "--dry-run",
        "--domain",
        "mirror.example.com",
        "--acme-email",
        "admin@example.com",
        "--max-connections",
        "2048",
    ]);
    assert!(output.status.success(), "{:?}", output.status);
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "dry run: nothing is changed",
        "to /usr/local/bin/mirrust, mode 0755",
        "write /etc/systemd/system/mirrust.service, mode 0644",
        "run: systemctl daemon-reload",
        "run: systemctl enable mirrust.service",
        "run: systemctl restart mirrust.service",
        "ExecStart=/usr/local/bin/mirrust \\\n    --listen 0.0.0.0:443 \\\n    --domain mirror.example.com \\\n    --acme-dir ${STATE_DIRECTORY} \\\n    --acme-email admin@example.com \\\n    --max-connections 2048\n",
        "[Install]\nWantedBy=multi-user.target\n",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
    assert!(!text.contains("LoadCredential="), "{text}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
#[cfg(unix)] // Uses Unix paths; the install command is for Linux.
fn install_dry_run_with_certificate_files_loads_them_as_credentials() {
    let output = mirrust(&[
        "install",
        "--dry-run",
        "--cert",
        "/etc/ssl/c.pem",
        "--key",
        "/etc/ssl/k.pem",
    ]);
    assert!(output.status.success(), "{:?}", output.status);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("LoadCredential=cert.pem:/etc/ssl/c.pem\n"),
        "{text}"
    );
    assert!(
        text.contains("LoadCredential=key.pem:/etc/ssl/k.pem\n"),
        "{text}"
    );
    assert!(
        text.contains("--cert ${CREDENTIALS_DIRECTORY}/cert.pem"),
        "{text}"
    );
}

#[test]
fn uninstall_dry_run_names_what_it_keeps() {
    let output = mirrust(&["uninstall", "--dry-run"]);
    assert!(output.status.success(), "{:?}", output.status);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("remove /etc/systemd/system/mirrust.service"),
        "{text}"
    );
    assert!(text.contains("remove /usr/local/bin/mirrust"), "{text}");
    assert!(text.contains("kept: /var/lib/mirrust"), "{text}");
}

#[test]
#[cfg(unix)] // Uses Unix paths; the install command is for Linux.
fn install_refuses_flag_combinations_that_make_no_sense() {
    for (flags, message) in [
        (
            &["install", "--cert", "/c.pem"][..],
            "--cert and --key go together",
        ),
        (
            &[
                "install",
                "--domain",
                "a.example.com",
                "--cert",
                "/c.pem",
                "--key",
                "/k.pem",
            ],
            "conflicts with --cert/--key",
        ),
        (
            &[
                "install",
                "--acme-staging",
                "--cert",
                "/c.pem",
                "--key",
                "/k.pem",
            ],
            "only mean something with --domain",
        ),
        (&["install", "--dry-run"], "give --domain NAME"),
        (
            &["uninstall", "--domain", "a.example.com"],
            "unknown flag --domain",
        ),
    ] {
        let output = mirrust(flags);
        assert!(!output.status.success(), "{flags:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(message), "{flags:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{flags:?}");
    }
}

#[test]
fn install_help_prints_its_usage() {
    let output = mirrust(&["install", "--help"]);
    assert!(output.status.success());
    let usage = String::from_utf8_lossy(&output.stdout);
    assert!(usage.contains("usage: mirrust install"), "{usage}");
    assert!(usage.contains("--dry-run"), "{usage}");
}
