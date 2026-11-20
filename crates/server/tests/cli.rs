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
