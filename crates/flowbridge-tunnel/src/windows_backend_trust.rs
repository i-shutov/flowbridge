//! Fail-closed Windows OpenSSH publisher check for the production supervisor.
//! A read-only handle denying write/delete sharing stays alive across
//! Authenticode validation, the -V check, and the actual child creation.
//! Do not export the checked path or signer identity in diagnostic snapshots.
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "SSH backend is not a trusted Microsoft-signed local executable",
    )
}

/// Query the actual Windows system directory, never PATH, WINDIR, or
/// another user-influenced environment variable.
fn system_directory() -> io::Result<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut text = vec![0u16; 32768];
    let n = unsafe { GetSystemDirectoryW(text.as_mut_ptr(), text.len() as u32) };
    if n == 0 || n as usize >= text.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsString::from_wide(&text[..n as usize])))
}

/// The only automatic Windows OpenSSH choice is the operating system's own
/// installation. The user can still pick a separately signed portable client
/// with an explicit absolute path.
pub(super) fn default_system_ssh() -> io::Result<PathBuf> {
    std::fs::canonicalize(system_directory()?.join("OpenSSH").join("ssh.exe"))
}

fn reject_reparse_components(path: &Path) -> io::Result<()> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    for ancestor in path.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor).map_err(|_| denied())?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(denied());
        }
    }
    Ok(())
}

/// Windows PowerShell 5.1 expects UTF-16LE Base64 for -EncodedCommand.
/// The only input is a compile-time constant; no untrusted value is encoded
/// into the PowerShell program or injected through its command-line parser.
fn encoded_powershell_command(script: &str) -> String {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(BASE64[(a >> 2) as usize] as char);
        out.push(BASE64[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn verify_microsoft_signature(executable: &Path) -> io::Result<()> {
    // Executed only from the kernel-resolved Windows system directory.
    // The PowerShell script is literal; the untrusted user path enters only
    // through an environment variable consumed by -LiteralPath, never as
    // PowerShell code, a -Command string interpolation or an SSH argument.
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$p = $env:FLOWBRIDGE_SIGNED_SSH_CANDIDATE
if ([string]::IsNullOrWhiteSpace($p)) { exit 14 }
if (-not [System.IO.File]::Exists($p)) { exit 18 }
# Never load a user-writable module named Microsoft.PowerShell.Security.
# PSHOME is the directory containing the trusted System32 PowerShell binary.
$env:PSModulePath = [System.IO.Path]::Combine($PSHOME, 'Modules')
try {
    Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
} catch {
    exit 29
}
try {
    $s = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
} catch {
    # Return only a bounded exception category, never the path/message.
    $name = $_.Exception.GetType().Name
    if ($name -eq 'FileNotFoundException') { exit 19 }
    if ($name -eq 'UnauthorizedAccessException') { exit 20 }
    if ($name -eq 'IOException') { exit 21 }
    if ($name -eq 'CommandNotFoundException') { exit 22 }
    if ($name -eq 'ParameterBindingException') { exit 23 }
    if ($name -eq 'ProviderInvocationException') { exit 24 }
    if ($name -eq 'InvalidOperationException') { exit 25 }
    if ($name -eq 'RuntimeException') { exit 26 }
    if ($name -eq 'ActionPreferenceStopException') { exit 27 }
    if ($name -eq 'SecurityException') { exit 28 }
    exit 17
}
if ($s.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    $null -eq $s.SignerCertificate) { exit 15 }
if ($s.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') { exit 16 }
exit 0
"#;
    let powershell = system_directory()?
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    reject_reparse_components(&powershell)?;
    // std::fs::canonicalize yields an extended \\?\C:\ path on Windows.
    // Windows PowerShell 5.1 providers are not required to accept that
    // prefix, so pass the equivalent local drive path as literal data.
    // Reject UNC and invalid/unpaired UTF-16 paths rather than guessing.
    let name = executable.to_str().ok_or_else(denied)?;
    let shell_path = name.strip_prefix(r"\\?\").unwrap_or(name);
    let raw = shell_path.as_bytes();
    if raw.len() < 3 || !raw[0].is_ascii_alphabetic() || raw[1] != b':' || raw[2] != b'\\' {
        return Err(denied());
    }
    let mut process = Command::new(powershell);
    let encoded = encoded_powershell_command(SCRIPT);
    process
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded.as_str(),
        ])
        .env("FLOWBRIDGE_SIGNED_SSH_CANDIDATE", shell_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000);
    let mut child = process.spawn().map_err(|_| denied())?;
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(result) = child.try_wait().map_err(|_| denied())? {
            if result.success() {
                return Ok(());
            }
            // Test-only stage code, never certificate subject, executable
            // paths or raw process output, in public GitHub Actions logs.
            #[cfg(test)]
            eprintln!("WIN_SSH_SIGNATURE_CHECK_STAGE_EXIT={:?}", result.code());
            return Err(denied());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(denied());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Caller MUST keep the returned guard alive through Command::spawn.
/// FILE_SHARE_READ disallows concurrent modification or deletion of the
/// executable via ordinary file handles while its signature is checked.
pub(super) fn verify_and_lock(executable: &Path) -> io::Result<File> {
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    if !executable.is_absolute()
        || executable
            .extension()
            .and_then(|s| s.to_str())
            .is_none_or(|s| !s.eq_ignore_ascii_case("exe"))
    {
        return Err(denied());
    }
    reject_reparse_components(executable)?;
    let guard = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(executable)
        .map_err(|_| denied())?;
    if !guard.metadata()?.is_file() {
        return Err(denied());
    }

    verify_microsoft_signature(executable)?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_test_executable_is_rejected_before_execution() {
        // Cargo-produced test executables are not Microsoft-signed; no code is
        // executed from them. The read-only verifier can still query a system
        // signer through the trusted system PowerShell.
        let current = std::env::current_exe().unwrap().canonicalize().unwrap();
        assert_eq!(
            verify_and_lock(&current).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn relative_and_non_executable_paths_fail_without_process_launch() {
        assert_eq!(
            verify_and_lock(Path::new("ssh.exe")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            verify_and_lock(Path::new("C:\\Windows\\fake-ssh.txt"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn powershell_encoding_contains_no_dynamic_backend_text() {
        assert_eq!(encoded_powershell_command("A"), "QQA=");
        assert_eq!(encoded_powershell_command(""), "");
        assert_eq!(encoded_powershell_command("AB"), "QQBCAA==");
    }

    #[test]
    fn signed_builtin_microsoft_ssh_passes_when_installed() {
        match default_system_ssh() {
            Ok(path) => {
                // Inspect safe stage outcomes, not paths/subjects/private
                // metadata, to distinguish CI environment from policy.
                assert!(
                    reject_reparse_components(&path).is_ok(),
                    "SYSTEM_SSH_REPARSE_COMPONENT_REJECTED"
                );
                let probe = OpenOptions::new()
                    .read(true)
                    .share_mode(0x0000_0001)
                    .open(&path);
                assert!(probe.is_ok(), "SYSTEM_SSH_LOCKED_FILE_OPEN_FAILED");
                drop(probe);
                // Localize a potential PowerShell cmdlet/argument/chain
                // failure separately from a guarded-open sharing failure.
                assert!(
                    verify_microsoft_signature(&path).is_ok(),
                    "SYSTEM_SSH_UNGUARDED_POWERSHELL_SIGNATURE_CHECK_FAILED"
                );
                // A packaged, signed Windows OpenSSH should be accepted. Do not
                // run ssh.exe in this read-only test.
                let _guard = verify_and_lock(&path).unwrap();
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("System OpenSSH not installed; positive test deferred");
            }
            Err(other) => panic!("system SSH discovery failed: {other:?}"),
        }
    }
}
