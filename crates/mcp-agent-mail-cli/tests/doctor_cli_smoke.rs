//! Pass-29 binary-boundary smoke tests for the doctor CLI.
//!
//! All prior doctor tests drive `dispatch_only` / `handle_*` directly
//! through the library API. That misses regressions at the binary
//! boundary: clap parsing, exit-code mapping, stdout vs stderr
//! separation, and CLI-mode dual-interface gating. These tests invoke
//! `am` via `std::process::Command` and verify the JSON envelopes
//! agents actually see.
//!
//! Tests are hermetic: each sets `STORAGE_ROOT` and `DATABASE_URL`
//! to a tempdir so production state is never touched.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

fn am_bin() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_BIN_EXE_am").expect("CARGO_BIN_EXE_am must be set"))
}

/// Run `am <args>` with CLI mode forced + storage isolated to
/// `tempdir`. Returns (exit_code, stdout, stderr). Inherits the
/// caller's PATH so `am` can find `git`, but overrides every env
/// var the doctor consults to keep production state untouched.
fn run_am(tempdir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let bin = am_bin();
    let db_url = format!("sqlite:///{}/storage.sqlite3", tempdir.display());
    let out = Command::new(bin)
        .args(args)
        .env("AM_INTERFACE_MODE", "cli")
        .env("STORAGE_ROOT", tempdir)
        .env("DATABASE_URL", db_url)
        .env("AM_DOCTOR_BACKUPS_DIR", tempdir.join(".doctor"))
        // Don't let the test inherit the operator's HTTP_BEARER_TOKEN
        // etc. — the doctor's wrong-mcp-url FM compares against the
        // canonical URL derived from HTTP_HOST/PORT/PATH.
        .env_remove("HTTP_BEARER_TOKEN")
        .env_remove("AM_DOCTOR_YES")
        .current_dir(tempdir)
        .output()
        .expect("invoke am");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn am_doctor_fix_only_writes_latest_run_artifacts() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let fm_id = mcp_agent_mail_cli::doctor::fixers::missing_gitignore_entry::FM_ID;
    let (code, stdout, stderr) = run_am(
        td.path(),
        &["doctor", "fix", "--only", fm_id, "--yes", "--json"],
    );
    assert_eq!(
        code, 0,
        "am doctor fix --only must exit 0; stderr: {stderr}"
    );

    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("fix-only must emit valid JSON");
    assert_eq!(envelope["fm_id"], fm_id);
    assert_eq!(envelope["actions_taken"], 1);
    assert_eq!(envelope["summary"]["total_findings"], 0);

    let run_id = envelope["run_id"].as_str().expect("run_id must be string");
    let run_dir = PathBuf::from(
        envelope["run_dir"]
            .as_str()
            .expect("mutating run_dir must be string"),
    );
    let report_path = run_dir.join("report.json");
    assert!(report_path.is_file(), "report.json must be persisted");
    assert!(run_dir.join("stdout.json").is_file());
    assert!(run_dir.join("report.md").is_file());
    assert!(run_dir.join("undo.sh").is_file());

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(report_path).expect("read report"))
            .expect("report must parse");
    assert_eq!(report["run_id"], run_id);
    assert_eq!(report["ok"], true);

    let latest = std::fs::read_link(td.path().join(".doctor").join("latest"))
        .expect("latest symlink must be updated");
    assert_eq!(latest, PathBuf::from("runs").join(run_id));
}

#[test]
fn am_doctor_fix_only_surfaces_latest_update_failure() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let doctor_root = td.path().join(".doctor");
    std::fs::create_dir(&doctor_root).expect("doctor root");
    std::fs::write(doctor_root.join("latest"), "operator data\n").expect("regular latest");
    let fm_id = mcp_agent_mail_cli::doctor::fixers::missing_gitignore_entry::FM_ID;

    let (code, stdout, stderr) = run_am(
        td.path(),
        &["doctor", "fix", "--only", fm_id, "--yes", "--json"],
    );

    assert_ne!(
        code, 0,
        "doctor fix must not report success when .doctor/latest cannot be updated"
    );
    assert!(
        stdout.trim().is_empty(),
        "failed latest update must not emit a success envelope on stdout"
    );
    assert!(
        stderr.contains("updating .doctor/latest"),
        "stderr must explain the latest-update failure: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(doctor_root.join("latest")).expect("latest preserved"),
        "operator data\n"
    );
}

#[test]
fn am_doctor_fix_only_dry_run_writes_no_persistent_run_dir() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let fm_id = mcp_agent_mail_cli::doctor::fixers::missing_gitignore_entry::FM_ID;
    let (code, stdout, stderr) = run_am(
        td.path(),
        &[
            "doctor",
            "fix",
            "--only",
            fm_id,
            "--dry-run",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(
        code, 0,
        "am doctor fix --only --dry-run must exit 0; stderr: {stderr}"
    );

    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("dry-run must emit valid JSON");
    assert_eq!(envelope["dry_run"], true);
    assert!(envelope["run_dir"].is_null());
    assert!(
        !td.path().join(".doctor").join("runs").exists(),
        "dry-run must not scaffold persistent doctor runs"
    );
}

#[test]
fn am_doctor_fix_dry_run_envelope_reports_ok_true_and_exit_zero() {
    // Pass-34D fresh-eyes (Codex F5): pre-fix, the envelope's
    // `ok` and `exit_code` fields conflated "the command
    // succeeded" with "no findings remain." A `--dry-run`
    // invocation that successfully PLANNED a fix (but didn't
    // apply it) reported `ok: false, exit_code: 1` in the
    // envelope even though the process exited 0. Agents
    // parsing the envelope saw apparent failures for clean
    // dry-run plans.
    let td = tempfile::TempDir::new().expect("tempdir");
    let gi = td.path().join(".gitignore");
    std::fs::write(&gi, "target/\n").expect("plant .gitignore");
    let fm_id = mcp_agent_mail_cli::doctor::fixers::missing_gitignore_entry::FM_ID;
    let (code, stdout, stderr) = run_am(
        td.path(),
        &[
            "doctor",
            "fix",
            "--only",
            fm_id,
            "--dry-run",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(code, 0, "dry-run process exit must be 0; stderr: {stderr}");
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("dry-run must emit valid JSON");
    assert_eq!(envelope["dry_run"], true);
    assert_eq!(
        envelope["ok"], true,
        "dry-run envelope must report ok=true even when findings remain (Codex F5)"
    );
    assert_eq!(
        envelope["exit_code"].as_i64(),
        Some(0),
        "dry-run envelope must report exit_code=0 (Codex F5)"
    );
}

#[test]
fn am_doctor_fixers_emits_registry_as_json() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let (code, stdout, stderr) = run_am(td.path(), &["doctor", "fixers", "--format", "json"]);
    assert_eq!(code, 0, "am doctor fixers must exit 0 (stderr: {stderr})");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("am doctor fixers must emit valid JSON");

    // Pass-14 contract: envelope has schema_version + tool + fixers[].
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["tool"], "am");
    let fixers = v["fixers"].as_array().expect("fixers must be an array");
    assert!(
        fixers.len() >= 9,
        "registry should have ≥9 FMs (pass-28 baseline), got {}",
        fixers.len()
    );
    assert_eq!(
        v["fixers_count"].as_u64().unwrap_or(0) as usize,
        fixers.len(),
        "fixers_count must match fixers[].length"
    );
    // Every entry must have id/severity/op_pattern/subsystem.
    for f in fixers {
        for required in ["id", "severity", "subsystem", "op_pattern", "auto_fixable"] {
            assert!(
                f.get(required).is_some(),
                "fixer entry missing field `{required}`: {f}"
            );
        }
    }
}

#[test]
fn am_doctor_fix_list_emits_list_all_envelope() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let (code, stdout, stderr) = run_am(td.path(), &["doctor", "fix", "--list", "--json"]);
    assert_eq!(
        code, 0,
        "am doctor fix --list (no --only) must exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("am doctor fix --list must emit valid JSON");

    // Pass-24 contract: mode + per_fm + skipped + counts.
    assert_eq!(v["mode"], "list_all");
    assert_eq!(v["tool"], "am");
    let per_fm = v["per_fm"]
        .as_array()
        .expect("per_fm must be an array (pass-24 contract)");
    let skipped = v["skipped"]
        .as_array()
        .expect("skipped must be an array (pass-24 contract)");
    assert!(
        v["fm_count"].as_u64().unwrap_or(0) >= 9,
        "fm_count should reflect ≥9 registered FMs"
    );
    // total_findings and total_actions_planned must be numbers.
    assert!(v["total_findings"].is_number());
    assert!(v["total_actions_planned"].is_number());
    // Every per_fm entry has fm_id + severity + subsystem + findings_count.
    for entry in per_fm {
        for required in [
            "fm_id",
            "severity",
            "subsystem",
            "op_pattern",
            "findings_count",
        ] {
            assert!(
                entry.get(required).is_some(),
                "per_fm entry missing field `{required}`: {entry}"
            );
        }
    }
    // Skipped entries (if any) must name the missing field.
    for entry in skipped {
        if entry["reason"] == "missing_input" {
            assert!(
                entry.get("missing_field").is_some(),
                "skipped[missing_input] must name missing_field"
            );
        }
    }
}

#[test]
fn am_doctor_explain_registered_fm_falls_back_to_registry() {
    // Pass-23 contract: explain on a registered FM id with no
    // prior run emits a mode="registry" envelope rather than
    // exiting 64.
    let td = tempfile::TempDir::new().expect("tempdir");
    let fm_id = mcp_agent_mail_cli::doctor::fixers::stale_archive_lock::FM_ID;
    let (code, stdout, stderr) = run_am(td.path(), &["doctor", "explain", fm_id]);
    assert_eq!(
        code, 0,
        "am doctor explain {fm_id} (cold) must exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("am doctor explain must emit valid JSON");
    assert_eq!(v["mode"], "registry");
    assert_eq!(v["finding_id"], fm_id);
    assert!(
        v["fixer_spec"].is_object(),
        "registry-fallback envelope must include fixer_spec"
    );
    assert_eq!(v["fixer_spec"]["id"], fm_id);
}

#[test]
fn am_doctor_explain_unknown_id_exits_64() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let (code, _stdout, stderr) =
        run_am(td.path(), &["doctor", "explain", "fm-not-a-real-id-pass29"]);
    assert_eq!(code, 64, "unknown id must exit 64; stderr: {stderr}");
}

#[test]
fn am_doctor_fixers_table_format_is_human_readable() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let (code, stdout, stderr) = run_am(td.path(), &["doctor", "fixers", "--format", "table"]);
    assert_eq!(code, 0, "table format must exit 0; stderr: {stderr}");
    // Header row contains known column names.
    assert!(
        stdout.contains("Sev") && stdout.contains("Subsystem") && stdout.contains("Op"),
        "table header must include Sev/Subsystem/Op columns; got:\n{stdout}"
    );
    // The fixer ids must appear in the table body.
    for fm_id in [
        "fm-archive-state-files-stale-archive-lock-from-dead-pid",
        "fm-doctor-state-files-dangling-latest-symlink",
        "fm-db-state-files-world-readable-storage-db",
    ] {
        assert!(
            stdout.contains(fm_id),
            "table output must list {fm_id}; got:\n{stdout}"
        );
    }
}

// ── GH#311: reservation parity fixer at the binary boundary ─────────────────

const PARITY_FM_ID: &str = "fm-db-state-files-reservation-db-archive-parity";
const PARITY_LIVE_GENERATION: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PARITY_FOREIGN_GENERATION: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PARITY_RELEASE_TS: i64 = 1_700_000_000_000_000;

/// Minimal reservation schema + one project/agent, with `db_identity` seeded
/// so the parity checker attributes artifact generations.
fn seed_parity_db(tempdir: &std::path::Path, reservation_rows: &str) {
    let db_path = tempdir.join("storage.sqlite3");
    let conn = mcp_agent_mail_db::CanonicalDbConn::open_file(db_path.to_string_lossy().as_ref())
        .expect("open scratch db");
    conn.execute_raw(&format!(
        "CREATE TABLE projects (id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, human_key TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
         CREATE TABLE agents (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, name TEXT NOT NULL, program TEXT NOT NULL, model TEXT NOT NULL, task_description TEXT, inception_ts INTEGER NOT NULL, last_active_ts INTEGER NOT NULL, capabilities TEXT, metadata TEXT);
         CREATE TABLE file_reservations (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, agent_id INTEGER NOT NULL, path_pattern TEXT NOT NULL, exclusive INTEGER NOT NULL, reason TEXT, created_ts INTEGER NOT NULL, expires_ts INTEGER NOT NULL, released_ts INTEGER);
         CREATE TABLE file_reservation_releases (reservation_id INTEGER PRIMARY KEY, released_ts INTEGER NOT NULL);
         CREATE TABLE db_identity (singleton INTEGER PRIMARY KEY CHECK (singleton = 0), generation_id TEXT NOT NULL);
         INSERT INTO projects VALUES (1, 'demo', '/synthetic/demo', 1);
         INSERT INTO agents VALUES (1, 1, 'BlueLake', 'codex-cli', 'gpt-5', NULL, 1, 1, NULL, NULL);
         INSERT INTO db_identity VALUES (0, '{PARITY_LIVE_GENERATION}');
         {reservation_rows}"
    ))
    .expect("seed scratch db");
}

fn parity_artifact_json(id: i64, path_pattern: &str, released_ts: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "id": id,
        "project": "demo",
        "agent": "BlueLake",
        "path_pattern": path_pattern,
        "exclusive": true,
        "reason": "synthetic fixture",
        "created_ts": 1,
        "expires_ts": 2,
        "released_ts": released_ts,
    }))
    .expect("serialize artifact")
}

fn parity_reservation_dir(tempdir: &std::path::Path) -> PathBuf {
    let dir = tempdir.join("projects/demo/file_reservations");
    std::fs::create_dir_all(&dir).expect("mkdir reservation archive");
    dir
}

fn run_parity_fix(tempdir: &std::path::Path) -> (i32, serde_json::Value, String) {
    let (code, stdout, stderr) = run_am(
        tempdir,
        &["doctor", "fix", "--only", PARITY_FM_ID, "--yes", "--json"],
    );
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("fix must emit JSON ({e}); stderr: {stderr}"));
    (code, envelope, stderr)
}

fn parity_remaining_findings(tempdir: &std::path::Path) -> u64 {
    let (code, stdout, stderr) = run_am(
        tempdir,
        &["doctor", "fix", "--only", PARITY_FM_ID, "--list", "--json"],
    );
    assert_eq!(code, 0, "--list must exit 0; stderr: {stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("list JSON");
    envelope["findings_count"].as_u64().expect("findings_count")
}

#[test]
fn am_doctor_fix_only_parity_rewrites_legacy_artifact_not_foreign_generation_and_exits_zero() {
    // GH#311 end to end: released live row, stale legacy `id-1.json`, and a
    // prior-generation `id-1-g<foreign>.json` that already records the release.
    let td = tempfile::TempDir::new().expect("tempdir");
    seed_parity_db(
        td.path(),
        &format!(
            "INSERT INTO file_reservations VALUES (1, 1, 1, 'src/demo.txt', 1, 'synthetic fixture', 1, 2, {PARITY_RELEASE_TS});
             INSERT INTO file_reservation_releases VALUES (1, {PARITY_RELEASE_TS});"
        ),
    );
    let dir = parity_reservation_dir(td.path());
    let legacy = dir.join("id-1.json");
    let foreign = dir.join(format!("id-1-g{PARITY_FOREIGN_GENERATION}.json"));
    std::fs::write(
        &legacy,
        parity_artifact_json(1, "src/demo.txt", serde_json::Value::Null),
    )
    .expect("legacy");
    let mut foreign_json: serde_json::Value = serde_json::from_slice(&parity_artifact_json(
        1,
        "src/demo.txt",
        serde_json::Value::String("2023-11-14T22:13:20Z".to_string()),
    ))
    .expect("foreign json");
    foreign_json["db_generation"] =
        serde_json::Value::String(PARITY_FOREIGN_GENERATION.to_string());
    std::fs::write(
        &foreign,
        serde_json::to_vec_pretty(&foreign_json).expect("serialize"),
    )
    .expect("foreign");
    let legacy_before = std::fs::read(&legacy).expect("legacy before");
    let foreign_before = std::fs::read(&foreign).expect("foreign before");
    assert_eq!(
        parity_remaining_findings(td.path()),
        1,
        "precondition: drift detected"
    );

    let (code, envelope, stderr) = run_parity_fix(td.path());
    assert_eq!(
        code, 0,
        "fix must exit 0 once drift is gone; stderr: {stderr}"
    );
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["exit_code"], 0);
    assert_eq!(envelope["actions_taken"], 1);
    assert_eq!(envelope["summary"]["total_findings"], 0);

    assert_ne!(std::fs::read(&legacy).expect("legacy after"), legacy_before);
    let legacy_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&legacy).expect("legacy after")).expect("json");
    assert_eq!(
        legacy_json["released_ts"],
        serde_json::json!(PARITY_RELEASE_TS)
    );
    assert_eq!(
        std::fs::read(&foreign).expect("foreign after"),
        foreign_before,
        "foreign-generation artifact must be byte-identical"
    );
    assert_eq!(
        parity_remaining_findings(td.path()),
        0,
        "second detector pass is clean"
    );
}

#[test]
fn am_doctor_fix_only_exit_code_matches_envelope_when_findings_remain() {
    // Detect-only drift (path_pattern) that no fixer reconciles: nothing is
    // mutated, findings remain → exit 1 (`findings_present_no_fix`), and the
    // process exit equals the envelope's `exit_code`.
    let td = tempfile::TempDir::new().expect("tempdir");
    seed_parity_db(
        td.path(),
        "INSERT INTO file_reservations VALUES (1, 1, 1, 'src/db-side.txt', 1, 'synthetic fixture', 1, 2, NULL);",
    );
    let dir = parity_reservation_dir(td.path());
    std::fs::write(
        dir.join("id-1.json"),
        parity_artifact_json(1, "src/archive-side.txt", serde_json::Value::Null),
    )
    .expect("legacy");

    let (code, envelope, stderr) = run_parity_fix(td.path());
    assert_eq!(
        code, 1,
        "findings remain, nothing mutated → exit 1; stderr: {stderr}"
    );
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["exit_code"], 1);
    assert_eq!(envelope["actions_taken"], 0);
    assert!(envelope["summary"]["total_findings"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn am_doctor_fix_only_exits_two_on_partial_fix() {
    // One reconcilable release drift (row 1) plus one detect-only path drift
    // (row 2): an action is taken, but a finding survives → exit 2
    // (`fix_partial`), matching the envelope.
    let td = tempfile::TempDir::new().expect("tempdir");
    seed_parity_db(
        td.path(),
        &format!(
            "INSERT INTO file_reservations VALUES (1, 1, 1, 'src/demo.txt', 1, 'synthetic fixture', 1, 2, {PARITY_RELEASE_TS});
             INSERT INTO file_reservation_releases VALUES (1, {PARITY_RELEASE_TS});
             INSERT INTO file_reservations VALUES (2, 1, 1, 'src/db-side.txt', 1, 'synthetic fixture', 1, 2, NULL);"
        ),
    );
    let dir = parity_reservation_dir(td.path());
    std::fs::write(
        dir.join("id-1.json"),
        parity_artifact_json(1, "src/demo.txt", serde_json::Value::Null),
    )
    .expect("row 1 legacy");
    std::fs::write(
        dir.join("id-2.json"),
        parity_artifact_json(2, "src/archive-side.txt", serde_json::Value::Null),
    )
    .expect("row 2 legacy");

    let (code, envelope, stderr) = run_parity_fix(td.path());
    assert_eq!(code, 2, "partial fix → exit 2; stderr: {stderr}");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["exit_code"], 2);
    assert_eq!(envelope["actions_taken"], 1);
    assert!(envelope["summary"]["total_findings"].as_u64().unwrap_or(0) >= 1);
}
