//! The directory where the account key and the issued certificate are kept between runs.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;

const ACCOUNT_FILE: &str = "account.json";
const CHAIN_FILE: &str = "certificate.pem";
const KEY_FILE: &str = "private-key.pem";
const NAMES_FILE: &str = "names.txt";
const FAILURE_FILE: &str = "last-failure.txt";

/// Mode of the cache directories: only the owner.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
/// Mode of every file in the cache: only the owner. The account key and the certificate's
/// private key are in there.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// The certificate authority to ask. Each has its own cache subdirectory, because an account
/// and a certificate from one are no use with the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateAuthority {
    /// Let's Encrypt production.
    LetsEncrypt,
    /// Let's Encrypt staging: not trusted by browsers, with far higher rate limits.
    LetsEncryptStaging,
}

impl CertificateAuthority {
    /// The name used in messages and as the cache subdirectory.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::LetsEncrypt => "letsencrypt",
            Self::LetsEncryptStaging => "letsencrypt-staging",
        }
    }

    /// The name for messages shown to the operator.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::LetsEncrypt => "Let's Encrypt",
            Self::LetsEncryptStaging => "Let's Encrypt staging",
        }
    }

    /// The ACME directory URL.
    #[must_use]
    pub fn directory_url(self) -> &'static str {
        match self {
            Self::LetsEncrypt => "https://acme-v02.api.letsencrypt.org/directory",
            Self::LetsEncryptStaging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        }
    }
}

/// The failed attempts in a row to get a certificate for some names, and when the last one
/// ended. It is kept on disk so that a restart does not start the waits over: Let's Encrypt
/// allows five failed validations per name and hour, and a restart loop would use them up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failures {
    /// How many attempts in a row failed.
    pub count: u32,
    /// When the last one failed.
    pub at: SystemTime,
}

/// A certificate chain and its private key as PEM text.
#[derive(Clone)]
pub struct StoredCert {
    /// The certificate chain, leaf first.
    pub chain_pem: String,
    /// The private key; never print it.
    pub key_pem: String,
}

impl std::fmt::Debug for StoredCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCert").finish_non_exhaustive()
    }
}

/// The on-disk state of one ACME client: the account credentials and the current certificate.
#[derive(Debug, Clone)]
pub struct CertCache {
    dir: PathBuf,
}

impl CertCache {
    /// Opens the cache for `authority` under `base`, creating the directories (mode 0700 on
    /// Unix) if they are missing. A directory that exists is left as it is.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be created.
    pub fn open(base: &Path, authority: CertificateAuthority) -> anyhow::Result<Self> {
        let dir = base.join(authority.name());
        create_private_dir(&dir)
            .with_context(|| format!("creating the ACME directory {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// The directory the files are in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The saved account credentials (JSON), if there are any.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but cannot be read.
    pub fn account(&self) -> io::Result<Option<String>> {
        read_optional(&self.dir.join(ACCOUNT_FILE))
    }

    /// Saves the account credentials; the file is readable by the owner only.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written.
    pub fn save_account(&self, json: &str) -> io::Result<()> {
        write_private(&self.dir.join(ACCOUNT_FILE), json)
    }

    /// Removes the saved account credentials, if there are any.
    ///
    /// # Errors
    ///
    /// Fails when the file exists and cannot be removed.
    pub fn forget_account(&self) -> io::Result<()> {
        match fs::remove_file(self.dir.join(ACCOUNT_FILE)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// The saved certificate, if it was issued for exactly `names`.
    ///
    /// # Errors
    ///
    /// Fails when a file exists but cannot be read.
    pub fn certificate(&self, names: &[String]) -> io::Result<Option<StoredCert>> {
        let Some(saved_names) = read_optional(&self.dir.join(NAMES_FILE))? else {
            return Ok(None);
        };
        if saved_names.trim_end() != names_text(names).trim_end() {
            return Ok(None);
        }
        let chain = read_optional(&self.dir.join(CHAIN_FILE))?;
        let key = read_optional(&self.dir.join(KEY_FILE))?;
        Ok(chain
            .zip(key)
            .map(|(chain_pem, key_pem)| StoredCert { chain_pem, key_pem }))
    }

    /// Saves the certificate issued for `names`. The key file is readable by the owner only.
    /// The names file of the previous certificate is removed first and written last, so a
    /// crash in between leaves a cache that is ignored, not a new key next to an old chain.
    ///
    /// # Errors
    ///
    /// Fails when a file cannot be written.
    pub fn save_certificate(&self, names: &[String], cert: &StoredCert) -> io::Result<()> {
        match fs::remove_file(self.dir.join(NAMES_FILE)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        write_private(&self.dir.join(KEY_FILE), &cert.key_pem)?;
        write_private(&self.dir.join(CHAIN_FILE), &cert.chain_pem)?;
        write_private(&self.dir.join(NAMES_FILE), &names_text(names))
    }
}

impl CertCache {
    /// The failed attempts recorded for exactly `names`, if any; a record for other names is
    /// not returned. An unreadable record counts as none.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but cannot be read.
    pub fn failures(&self, names: &[String]) -> io::Result<Option<Failures>> {
        let Some(text) = read_optional(&self.dir.join(FAILURE_FILE))? else {
            return Ok(None);
        };
        Ok(parse_failures(&text, names))
    }

    /// Records that `failures.count` attempts in a row for `names` have failed.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written.
    pub fn save_failures(&self, names: &[String], failures: Failures) -> io::Result<()> {
        let seconds = failures
            .at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let text = format!("{} {seconds}\n{}", failures.count, names_text(names));
        write_private(&self.dir.join(FAILURE_FILE), &text)
    }

    /// Forgets the recorded failures, after a success.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but cannot be removed.
    pub fn clear_failures(&self) -> io::Result<()> {
        match fs::remove_file(self.dir.join(FAILURE_FILE)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

/// Reads what [`CertCache::save_failures`] wrote: `count seconds`, then the names.
fn parse_failures(text: &str, names: &[String]) -> Option<Failures> {
    let (first, saved_names) = text.split_once('\n')?;
    let (count, seconds) = first.split_once(' ')?;
    if saved_names != names_text(names) {
        return None;
    }
    Some(Failures {
        count: count.parse().ok().filter(|&count| count > 0)?,
        at: UNIX_EPOCH + Duration::from_secs(seconds.parse().ok()?),
    })
}

/// The names, sorted, one per line.
fn names_text(names: &[String]) -> String {
    let mut sorted: Vec<&str> = names.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.iter().fold(String::new(), |mut text, name| {
        text.push_str(name);
        text.push('\n');
        text
    })
}

fn read_optional(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(DIR_MODE);
    }
    builder.create(dir)
}

/// Writes `text` to `path` through a temporary file and a rename, so a reader never sees half
/// a file; the file is created readable by its owner only.
fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    // A leftover from a crash would keep its old mode.
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = create_private_file(&temporary)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync_parent(path)
}

/// Flushes the directory of `path`, so that a rename in it survives a crash. Not possible on
/// Windows, where opening a directory fails.
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(FILE_MODE);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(name: &str) -> PathBuf {
        let base =
            std::env::temp_dir().join(format!("mirrust-acme-cache-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        base
    }

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|&value| value.to_owned()).collect()
    }

    #[test]
    fn a_saved_certificate_comes_back_only_for_the_same_names() {
        let base = temp_base("roundtrip");
        let cache = CertCache::open(&base, CertificateAuthority::LetsEncryptStaging)
            .expect("open the cache");
        assert!(cache.dir().ends_with("letsencrypt-staging"));
        assert!(cache.account().expect("read").is_none());
        assert!(
            cache
                .certificate(&names(&["a.example.com"]))
                .expect("read")
                .is_none()
        );

        let cert = StoredCert {
            chain_pem: "CHAIN".into(),
            key_pem: "KEY".into(),
        };
        cache
            .save_certificate(&names(&["b.example.com", "a.example.com"]), &cert)
            .expect("save");
        cache.save_account("{}").expect("save account");
        assert_eq!(cache.account().expect("read").as_deref(), Some("{}"));

        let same = cache
            .certificate(&names(&["a.example.com", "b.example.com"]))
            .expect("read")
            .expect("same names, any order");
        assert_eq!(
            (same.chain_pem.as_str(), same.key_pem.as_str()),
            ("CHAIN", "KEY")
        );
        assert!(
            cache
                .certificate(&names(&["a.example.com"]))
                .expect("read")
                .is_none()
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_save_that_fails_midway_leaves_no_names_so_the_old_files_are_ignored() {
        let base = temp_base("midway");
        let cache = CertCache::open(&base, CertificateAuthority::LetsEncrypt).expect("open");
        let list = names(&["a.example.com"]);
        let old = StoredCert {
            chain_pem: "OLD CHAIN".into(),
            key_pem: "OLD KEY".into(),
        };
        cache.save_certificate(&list, &old).expect("save");
        // Writing the chain fails: a directory is in the way of the rename.
        fs::remove_file(cache.dir().join(CHAIN_FILE)).expect("remove");
        fs::create_dir(cache.dir().join(CHAIN_FILE)).expect("block");
        let new = StoredCert {
            chain_pem: "NEW CHAIN".into(),
            key_pem: "NEW KEY".into(),
        };
        cache.save_certificate(&list, &new).expect_err("blocked");
        assert!(
            cache.certificate(&list).expect("read").is_none(),
            "a new key next to an old chain must not be served"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn failures_are_kept_for_the_same_names_only_and_can_be_cleared() {
        let base = temp_base("failures");
        let cache = CertCache::open(&base, CertificateAuthority::LetsEncrypt).expect("open");
        let list = names(&["b.example.com", "a.example.com"]);
        assert_eq!(cache.failures(&list).expect("read"), None);

        let failures = Failures {
            count: 3,
            at: UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        };
        cache.save_failures(&list, failures).expect("save");
        let reordered = names(&["a.example.com", "b.example.com"]);
        assert_eq!(cache.failures(&reordered).expect("read"), Some(failures));
        let other = names(&["a.example.com"]);
        assert_eq!(cache.failures(&other).expect("read"), None, "other names");

        cache.save_failures(&list, failures).expect("save again");
        cache.clear_failures().expect("clear");
        cache.clear_failures().expect("clearing twice is fine");
        assert_eq!(cache.failures(&list).expect("read"), None);

        fs::write(cache.dir().join(FAILURE_FILE), "garbage").expect("write");
        assert_eq!(cache.failures(&list).expect("read"), None, "unreadable");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn the_production_and_staging_caches_are_apart() {
        let base = temp_base("apart");
        let production = CertCache::open(&base, CertificateAuthority::LetsEncrypt).expect("open");
        let staging =
            CertCache::open(&base, CertificateAuthority::LetsEncryptStaging).expect("open");
        production.save_account("prod").expect("save");
        assert!(staging.account().expect("read").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn directories_are_0700_and_files_0600_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;

        let base = temp_base("modes");
        let cache = CertCache::open(&base, CertificateAuthority::LetsEncrypt).expect("open");
        assert_eq!(mode(&base), 0o700, "the base directory");
        assert_eq!(mode(cache.dir()), 0o700, "the cache directory");

        let cert = StoredCert {
            chain_pem: "CHAIN".into(),
            key_pem: "KEY".into(),
        };
        cache.save_account("{}").expect("save account");
        cache
            .save_certificate(&names(&["a.example.com"]), &cert)
            .expect("save certificate");
        // Saving again goes through the temporary file and the rename a second time.
        cache
            .save_certificate(&names(&["a.example.com"]), &cert)
            .expect("save again");
        for file in [ACCOUNT_FILE, CHAIN_FILE, KEY_FILE, NAMES_FILE] {
            assert_eq!(mode(&cache.dir().join(file)), 0o600, "{file}");
        }
        let leftovers: Vec<_> = fs::read_dir(cache.dir())
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn the_debug_output_of_a_stored_certificate_hides_the_key() {
        let cert = StoredCert {
            chain_pem: "CHAIN".into(),
            key_pem: "SECRET".into(),
        };
        assert!(!format!("{cert:?}").contains("SECRET"));
    }
}
