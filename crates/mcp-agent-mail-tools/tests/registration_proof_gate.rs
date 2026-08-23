//! End-to-end tests for the optional registration proof gate wired into the
//! live registration entry points.
//!
//! These exercise the REAL tool functions (`register_agent`,
//! `create_agent_identity`, `macro_start_session`, `macro_prepare_thread`)
//! against a real SQLite-backed pool, toggling the gate through configuration
//! exactly as an operator would, and asserting:
//!
//! - disabled gate  => registration works with no proof (unchanged behavior);
//! - enabled gate + no proof   => every entry point fails closed (`PROOF_REQUIRED`);
//! - enabled gate + valid proof => registration succeeds through the tool and
//!   through a macro (proving macros forward the proof and cannot bypass it).

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use fastmcp::prelude::McpContext;
use mcp_agent_mail_core::{Config, config::with_process_env_overrides_for_test};
use mcp_agent_mail_tools::{
    create_agent_identity, deregister_agent, ensure_project, macro_prepare_thread,
    macro_start_session, register_agent, reply_message, request_contact, retire_agent,
    send_message, unretire_agent, whois,
};
use serde_json::Value;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Capabilities `register_agent` grants by default; the proof must authorize a
/// superset of these (kept in sync with `identity::DEFAULT_AGENT_CAPABILITIES`).
const DEFAULT_CAPS: &[&str] = &[
    "send_message",
    "fetch_inbox",
    "file_reservation_paths",
    "acknowledge_message",
];

fn unique_suffix() -> u64 {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    u64::try_from(micros)
        .unwrap_or(u64::MAX)
        .wrapping_add(TEST_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(0)
}

/// Run `f` serially with a fresh temp DB/storage plus any extra env overrides
/// (used to toggle the proof gate). Mirrors the harness used by the other
/// parity integration tests.
fn run_with_env<F, Fut, T>(extra: &[(&str, &str)], f: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let _lock = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let suffix = unique_suffix();
    let database_url = format!("sqlite:///tmp/proof-gate-{suffix}.sqlite3");
    let storage_root = format!("/tmp/proof-gate-storage-{suffix}");
    let mut env: Vec<(&str, &str)> = vec![
        ("DATABASE_URL", database_url.as_str()),
        ("STORAGE_ROOT", storage_root.as_str()),
    ];
    env.extend_from_slice(extra);
    with_process_env_overrides_for_test(&env, || {
        Config::reset_cached();
        let cx = Cx::for_testing();
        let rt = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        rt.block_on(f(cx))
    })
}

fn error_type(err: &fastmcp::McpError) -> String {
    err.data
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|root| root.get("error"))
        .and_then(Value::as_object)
        .and_then(|e| e.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("<no type>")
        .to_string()
}

async fn setup_reply_lifecycle_fixture(
    ctx: &McpContext,
    label: &str,
) -> (String, i64, String, String) {
    let project_key = format!("/tmp/{label}-{}", unique_suffix());
    ensure_project(ctx, project_key.clone(), None)
        .await
        .expect("ensure_project");

    let sender = create_agent_identity(
        ctx,
        project_key.clone(),
        "codex-cli".to_string(),
        "gpt-5".to_string(),
        Some("BlueLake".to_string()),
        Some("reply sender".to_string()),
        None,
        true,
        None,
        None,
    )
    .await
    .expect("create reply sender");
    let sender: Value = serde_json::from_str(&sender).expect("sender identity JSON");
    let sender_token = sender["registration_token"]
        .as_str()
        .expect("sender registration token")
        .to_string();

    let recipient = create_agent_identity(
        ctx,
        project_key.clone(),
        "claude-code".to_string(),
        "opus-4.1".to_string(),
        Some("GreenCastle".to_string()),
        Some("original message sender".to_string()),
        None,
        true,
        None,
        None,
    )
    .await
    .expect("create original sender");
    let recipient: Value = serde_json::from_str(&recipient).expect("recipient identity JSON");
    let recipient_token = recipient["registration_token"]
        .as_str()
        .expect("recipient registration token")
        .to_string();

    let original = send_message(
        ctx,
        project_key.clone(),
        "GreenCastle".to_string(),
        vec!["BlueLake".to_string()],
        "reply lifecycle".to_string(),
        "original message".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(true),
        Some(recipient_token.clone()),
        None,
    )
    .await
    .expect("send original message");
    let original: Value = serde_json::from_str(&original).expect("original message JSON");
    let message_id = original
        .pointer("/deliveries/0/payload/id")
        .and_then(Value::as_i64)
        .expect("original message id");

    (project_key, message_id, sender_token, recipient_token)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Reproduce the verifier's canonical signed bytes (see
/// `mcp_agent_mail_tools::proof_gate::canonical_message`). Any external signer
/// would reproduce exactly this.
#[allow(clippy::too_many_arguments)] // mirrors the signed claim set 1:1
fn canonical_message(
    identity: &str,
    project_key: &str,
    program: &str,
    model: &str,
    caps: &[&str],
    issued_at: i64,
    expires_at: i64,
    nonce: &str,
) -> String {
    let mut c: Vec<String> = caps
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    c.sort();
    c.dedup();
    format!(
        "agent-mail-registration-proof:v1\n\
         identity={identity}\n\
         project_key={project_key}\n\
         program={program}\n\
         model={model}\n\
         capabilities={caps}\n\
         issued_at={issued_at}\n\
         expires_at={expires_at}\n\
         nonce={nonce}",
        caps = c.join(","),
    )
}

/// Build a valid signed proof bundle JSON string for the given registration.
#[allow(clippy::too_many_arguments)]
fn signed_proof(
    key: &SigningKey,
    identity: &str,
    project_key: &str,
    program: &str,
    model: &str,
    caps: &[&str],
    issued_at: i64,
    expires_at: i64,
    nonce: &str,
) -> String {
    let msg = canonical_message(
        identity,
        project_key,
        program,
        model,
        caps,
        issued_at,
        expires_at,
        nonce,
    );
    let sig = key.sign(msg.as_bytes());
    serde_json::json!({
        "claims": {
            "identity": identity,
            "project_key": project_key,
            "program": program,
            "model": model,
            "capabilities": caps,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": nonce,
        },
        "public_key": b64(key.verifying_key().as_bytes()),
        "signature": b64(&sig.to_bytes()),
    })
    .to_string()
}

#[test]
fn disabled_gate_registers_without_proof() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/proof-off-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        // register_agent with NO proof still works when the gate is off.
        register_agent(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("BlueLake".to_string()),
            Some("proof gate disabled".to_string()),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("register_agent should succeed with gate disabled");

        // create_agent_identity with NO proof also works.
        create_agent_identity(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("GreenCastle".to_string()),
            Some("proof gate disabled".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create_agent_identity should succeed with gate disabled");

        // macro_start_session with NO proof also works.
        macro_start_session(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("RedStone".to_string()),
            Some("proof gate disabled".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("macro_start_session should succeed with gate disabled");
    });
}

#[test]
fn create_identity_can_hide_returned_registration_token() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/token-hidden-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        let raw = create_agent_identity(
            &ctx,
            project_key,
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("GreenCastle".to_string()),
            Some("transcript-safe identity".to_string()),
            None,
            false,
            None,
            None,
        )
        .await
        .expect("create_agent_identity");
        let response: Value = serde_json::from_str(&raw).expect("identity response JSON");

        assert!(response.get("registration_token").is_none());
        assert_eq!(
            response.get("registration_token_returned"),
            Some(&Value::Bool(false))
        );
    });
}

#[test]
fn retire_and_unretire_agent_return_python_status_contract() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/lifecycle-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");
        let created = create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("GreenCastle".to_string()),
            Some("lifecycle contract".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create_agent_identity");
        let created: Value = serde_json::from_str(&created).expect("created identity JSON");
        let token = created["registration_token"]
            .as_str()
            .expect("registration token")
            .to_string();

        let retired = retire_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(token.clone()),
            None,
        )
        .await
        .expect("retire_agent");
        let retired: Value = serde_json::from_str(&retired).expect("retire response JSON");
        assert_eq!(retired["status"], "retired");
        assert_eq!(retired["agent_name"], "GreenCastle");
        assert_eq!(retired["project_key"], project_key);

        let active = unretire_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(token),
            None,
        )
        .await
        .expect("unretire_agent");
        let active: Value = serde_json::from_str(&active).expect("unretire response JSON");
        assert_eq!(active["status"], "active");
        assert_eq!(active["agent_name"], "GreenCastle");
        assert_eq!(active["project_key"], project_key);
    });
}

#[test]
fn whois_reports_retirement_timestamp() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/whois-retired-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");
        let created = create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("GreenCastle".to_string()),
            Some("whois retirement contract".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create_agent_identity");
        let created: Value = serde_json::from_str(&created).expect("created identity JSON");
        let token = created["registration_token"]
            .as_str()
            .expect("registration token")
            .to_string();
        retire_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(token),
            None,
        )
        .await
        .expect("retire agent");

        let profile = whois(
            &ctx,
            project_key,
            "GreenCastle".to_string(),
            Some(false),
            None,
        )
        .await
        .expect("whois retired agent");
        let profile: Value = serde_json::from_str(&profile).expect("whois response JSON");

        assert!(profile["retired_at"].as_str().is_some());
    });
}

#[test]
#[allow(clippy::too_many_lines)]
fn retired_recipient_is_rejected_until_unretired() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/retired-routing-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("BlueLake".to_string()),
            Some("active sender".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create sender");
        let recipient = create_agent_identity(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("GreenCastle".to_string()),
            Some("retirement routing target".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create recipient");
        let recipient: Value = serde_json::from_str(&recipient).expect("recipient identity JSON");
        let recipient_token = recipient["registration_token"]
            .as_str()
            .expect("recipient registration token")
            .to_string();

        retire_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(recipient_token.clone()),
            None,
        )
        .await
        .expect("retire recipient");

        let err = send_message(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            vec!["GreenCastle".to_string()],
            "routing while retired".to_string(),
            "must not be delivered".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            None,
        )
        .await
        .expect_err("retired recipient must reject new messages");
        assert_eq!(error_type(&err), "AGENT_RETIRED");

        unretire_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(recipient_token),
            None,
        )
        .await
        .expect("unretire recipient");

        send_message(
            &ctx,
            project_key,
            "BlueLake".to_string(),
            vec!["GreenCastle".to_string()],
            "routing restored".to_string(),
            "delivery resumes after unretire".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            None,
        )
        .await
        .expect("unretired recipient accepts messages");
    });
}

#[test]
#[allow(clippy::too_many_lines)]
fn retired_sender_cannot_reply_to_messages() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/retired-reply-sender-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        let sender = create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("BlueLake".to_string()),
            Some("reply sender".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create reply sender");
        let sender: Value = serde_json::from_str(&sender).expect("sender identity JSON");
        let sender_token = sender["registration_token"]
            .as_str()
            .expect("sender registration token")
            .to_string();

        let recipient = create_agent_identity(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("GreenCastle".to_string()),
            Some("original message sender".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create original sender");
        let recipient: Value = serde_json::from_str(&recipient).expect("recipient identity JSON");
        let recipient_token = recipient["registration_token"]
            .as_str()
            .expect("recipient registration token")
            .to_string();

        let original = send_message(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            vec!["BlueLake".to_string()],
            "reply lifecycle".to_string(),
            "original message".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
            Some(recipient_token),
            None,
        )
        .await
        .expect("send original message");
        let original: Value = serde_json::from_str(&original).expect("original message JSON");
        let message_id = original
            .pointer("/deliveries/0/payload/id")
            .and_then(Value::as_i64)
            .expect("original message id");

        retire_agent(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            Some(sender_token.clone()),
            None,
        )
        .await
        .expect("retire reply sender");

        let err = reply_message(
            &ctx,
            project_key,
            message_id,
            "BlueLake".to_string(),
            "must not be delivered".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(sender_token),
            None,
        )
        .await
        .expect_err("retired sender must not reply");
        assert_eq!(error_type(&err), "AGENT_RETIRED");
    });
}

#[test]
fn deregistered_sender_cannot_reply_to_messages() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let (project_key, message_id, sender_token, _) =
            setup_reply_lifecycle_fixture(&ctx, "deregistered-reply-sender").await;

        deregister_agent(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            Some(sender_token.clone()),
            None,
        )
        .await
        .expect("deregister reply sender");

        let err = reply_message(
            &ctx,
            project_key,
            message_id,
            "BlueLake".to_string(),
            "must not be delivered".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(sender_token),
            None,
        )
        .await
        .expect_err("deregistered sender must not reply");
        assert_eq!(error_type(&err), "AGENT_DEREGISTERED");
    });
}

#[test]
fn inactive_recipient_cannot_receive_replies() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let (project_key, message_id, sender_token, recipient_token) =
            setup_reply_lifecycle_fixture(&ctx, "inactive-reply-recipient").await;

        retire_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(recipient_token.clone()),
            None,
        )
        .await
        .expect("retire reply recipient");

        let retired_err = reply_message(
            &ctx,
            project_key.clone(),
            message_id,
            "BlueLake".to_string(),
            "must not reach retired recipient".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(sender_token.clone()),
            None,
        )
        .await
        .expect_err("retired recipient must reject replies");
        assert_eq!(error_type(&retired_err), "AGENT_RETIRED");

        unretire_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(recipient_token.clone()),
            None,
        )
        .await
        .expect("unretire reply recipient");
        deregister_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(recipient_token),
            None,
        )
        .await
        .expect("deregister reply recipient");

        let deregistered_err = reply_message(
            &ctx,
            project_key,
            message_id,
            "BlueLake".to_string(),
            "must not reach deregistered recipient".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(sender_token),
            None,
        )
        .await
        .expect_err("deregistered recipient must reject replies");
        assert_eq!(error_type(&deregistered_err), "AGENT_DEREGISTERED");
    });
}

#[test]
#[allow(clippy::too_many_lines)]
fn retired_sender_is_rejected_until_unretired() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/retired-sender-routing-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        let sender = create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("BlueLake".to_string()),
            Some("retirement routing sender".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create sender");
        let sender: Value = serde_json::from_str(&sender).expect("sender identity JSON");
        let sender_token = sender["registration_token"]
            .as_str()
            .expect("sender registration token")
            .to_string();
        create_agent_identity(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("GreenCastle".to_string()),
            Some("active recipient".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create recipient");

        retire_agent(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            Some(sender_token.clone()),
            None,
        )
        .await
        .expect("retire sender");

        let err = send_message(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            vec!["GreenCastle".to_string()],
            "retired sender routing".to_string(),
            "must not be delivered".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            None,
        )
        .await
        .expect_err("retired sender must reject new messages");
        assert_eq!(error_type(&err), "AGENT_RETIRED");

        unretire_agent(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            Some(sender_token),
            None,
        )
        .await
        .expect("unretire sender");

        send_message(
            &ctx,
            project_key,
            "BlueLake".to_string(),
            vec!["GreenCastle".to_string()],
            "sender routing restored".to_string(),
            "delivery resumes after unretire".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            None,
        )
        .await
        .expect("unretired sender can send messages");
    });
}

#[test]
fn deregister_agent_returns_python_status_contract() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/deregister-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");
        let created = create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("GreenCastle".to_string()),
            Some("session cleanup".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create_agent_identity");
        let created: Value = serde_json::from_str(&created).expect("created identity JSON");
        let token = created["registration_token"]
            .as_str()
            .expect("registration token")
            .to_string();

        let response = deregister_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(token),
            None,
        )
        .await
        .expect("deregister_agent");
        let response: Value = serde_json::from_str(&response).expect("deregister response JSON");
        assert_eq!(response["status"], "deregistered");
        assert_eq!(response["agent_name"], "GreenCastle");
        assert_eq!(response["project_key"], project_key);
    });
}

#[test]
fn deregistered_sender_cannot_send_messages() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/deregistered-sender-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        let sender = create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("BlueLake".to_string()),
            Some("session cleanup sender".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create sender");
        let sender: Value = serde_json::from_str(&sender).expect("sender identity JSON");
        let sender_token = sender["registration_token"]
            .as_str()
            .expect("sender registration token")
            .to_string();
        create_agent_identity(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("GreenCastle".to_string()),
            Some("active recipient".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create recipient");

        deregister_agent(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            Some(sender_token),
            None,
        )
        .await
        .expect("deregister sender");

        let err = send_message(
            &ctx,
            project_key,
            "BlueLake".to_string(),
            vec!["GreenCastle".to_string()],
            "deregistered sender routing".to_string(),
            "must not be delivered".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            None,
        )
        .await
        .expect_err("deregistered sender must reject new messages");
        assert_eq!(error_type(&err), "AGENT_DEREGISTERED");
    });
}

#[test]
fn deregistered_recipient_cannot_receive_messages() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/deregistered-recipient-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        create_agent_identity(
            &ctx,
            project_key.clone(),
            "codex-cli".to_string(),
            "gpt-5".to_string(),
            Some("BlueLake".to_string()),
            Some("active sender".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create sender");
        let recipient = create_agent_identity(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("GreenCastle".to_string()),
            Some("session cleanup recipient".to_string()),
            None,
            true,
            None,
            None,
        )
        .await
        .expect("create recipient");
        let recipient: Value = serde_json::from_str(&recipient).expect("recipient identity JSON");
        let recipient_token = recipient["registration_token"]
            .as_str()
            .expect("recipient registration token")
            .to_string();

        deregister_agent(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(recipient_token),
            None,
        )
        .await
        .expect("deregister recipient");

        let err = send_message(
            &ctx,
            project_key,
            "BlueLake".to_string(),
            vec!["GreenCastle".to_string()],
            "deregistered recipient routing".to_string(),
            "must not be delivered".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            None,
        )
        .await
        .expect_err("deregistered recipient must reject new messages");
        assert_eq!(error_type(&err), "AGENT_DEREGISTERED");
    });
}

#[test]
fn enabled_gate_blocks_every_entry_point_without_proof() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let trusted = b64(key.verifying_key().as_bytes());
    run_with_env(
        &[
            ("AM_REGISTRATION_PROOF_GATE_ENABLED", "true"),
            ("AM_REGISTRATION_PROOF_TRUSTED_KEYS", trusted.as_str()),
        ],
        |cx| async move {
            let ctx = McpContext::new(cx.clone(), 1);
            let project_key = format!("/tmp/proof-on-{}", unique_suffix());
            ensure_project(&ctx, project_key.clone(), None)
                .await
                .expect("ensure_project");

            // 1. register_agent
            let err = register_agent(
                &ctx,
                project_key.clone(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("BlueLake".to_string()),
                Some("no proof".to_string()),
                None,
                None,
                None,
                None,
            )
            .await
            .expect_err("register_agent must fail closed without proof");
            assert_eq!(error_type(&err), "PROOF_REQUIRED");

            // 2. create_agent_identity
            let err = create_agent_identity(
                &ctx,
                project_key.clone(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("GreenCastle".to_string()),
                Some("no proof".to_string()),
                None,
                true,
                None,
                None,
            )
            .await
            .expect_err("create_agent_identity must fail closed without proof");
            assert_eq!(error_type(&err), "PROOF_REQUIRED");

            // 3. macro_start_session
            let err = macro_start_session(
                &ctx,
                project_key.clone(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("RedStone".to_string()),
                Some("no proof".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect_err("macro_start_session must fail closed without proof");
            assert_eq!(error_type(&err), "PROOF_REQUIRED");

            // 4. macro_prepare_thread (register_if_missing defaults to true)
            let err = macro_prepare_thread(
                &ctx,
                project_key.clone(),
                "br-1".to_string(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("AmberRiver".to_string()),
                Some("no proof".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect_err("macro_prepare_thread must fail closed without proof");
            assert_eq!(error_type(&err), "PROOF_REQUIRED");
        },
    );
}

#[test]
fn enabled_gate_allows_valid_proof_through_tool_and_macro() {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let trusted = b64(key.verifying_key().as_bytes());
    run_with_env(
        &[
            ("AM_REGISTRATION_PROOF_GATE_ENABLED", "true"),
            ("AM_REGISTRATION_PROOF_TRUSTED_KEYS", trusted.as_str()),
        ],
        |cx| async move {
            let ctx = McpContext::new(cx.clone(), 1);
            let project_key = format!("/tmp/proof-ok-{}", unique_suffix());
            ensure_project(&ctx, project_key.clone(), None)
                .await
                .expect("ensure_project");

            let now = now_unix();

            // Direct tool: valid proof for BlueLake registers.
            let proof = signed_proof(
                &key,
                "BlueLake",
                &project_key,
                "claude-code",
                "opus-4.1",
                DEFAULT_CAPS,
                now,
                now + 120,
                "nonce-tool",
            );
            register_agent(
                &ctx,
                project_key.clone(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("BlueLake".to_string()),
                Some("valid proof".to_string()),
                None,
                None,
                None,
                Some(proof),
            )
            .await
            .expect("register_agent should succeed with a valid proof");

            // Macro: valid proof forwarded through macro_start_session registers.
            let macro_proof = signed_proof(
                &key,
                "GreenCastle",
                &project_key,
                "claude-code",
                "opus-4.1",
                DEFAULT_CAPS,
                now,
                now + 120,
                "nonce-macro",
            );
            macro_start_session(
                &ctx,
                project_key.clone(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("GreenCastle".to_string()),
                Some("valid proof".to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
                Some(macro_proof),
            )
            .await
            .expect("macro_start_session should succeed with a valid proof");
        },
    );
}

#[test]
fn enabled_gate_rejects_replayed_nonce_durably() {
    let key = SigningKey::from_bytes(&[23u8; 32]);
    let trusted = b64(key.verifying_key().as_bytes());
    run_with_env(
        &[
            ("AM_REGISTRATION_PROOF_GATE_ENABLED", "true"),
            ("AM_REGISTRATION_PROOF_TRUSTED_KEYS", trusted.as_str()),
        ],
        |cx| async move {
            let ctx = McpContext::new(cx.clone(), 1);
            let project_key = format!("/tmp/proof-replay-{}", unique_suffix());
            ensure_project(&ctx, project_key.clone(), None)
                .await
                .expect("ensure_project");

            let now = now_unix();

            // First registration with nonce "shared-nonce" succeeds and durably
            // records the nonce in the DB.
            let proof1 = signed_proof(
                &key,
                "BlueLake",
                &project_key,
                "claude-code",
                "opus-4.1",
                DEFAULT_CAPS,
                now,
                now + 120,
                "shared-nonce",
            );
            register_agent(
                &ctx,
                project_key.clone(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("BlueLake".to_string()),
                Some("first".to_string()),
                None,
                None,
                None,
                Some(proof1),
            )
            .await
            .expect("first registration with a fresh nonce succeeds");

            // A DIFFERENT, independently-valid proof (different agent) that REUSES
            // the same nonce must be rejected as a replay. The rejection comes
            // from the durable DB store — the only nonce record now that the
            // in-memory store is gone — so it also holds across process restarts
            // and separate processes, which the previous in-memory store could
            // not guarantee. Each register_agent call is an independent tool
            // invocation, exactly the cross-invocation scenario that matters.
            let proof2 = signed_proof(
                &key,
                "GreenCastle",
                &project_key,
                "claude-code",
                "opus-4.1",
                DEFAULT_CAPS,
                now,
                now + 120,
                "shared-nonce",
            );
            let err = register_agent(
                &ctx,
                project_key.clone(),
                "claude-code".to_string(),
                "opus-4.1".to_string(),
                Some("GreenCastle".to_string()),
                Some("replay".to_string()),
                None,
                None,
                None,
                Some(proof2),
            )
            .await
            .expect_err("reusing a consumed nonce must fail closed");
            assert_eq!(error_type(&err), "PROOF_REPLAYED_NONCE");

            // The replayed registration must not have created the identity.
            let err = whois(
                &ctx,
                project_key.clone(),
                "GreenCastle".to_string(),
                Some(false),
                None,
            )
            .await
            .expect_err("replayed registration must not create the identity");
            assert_eq!(error_type(&err), "AGENT_NOT_FOUND");
        },
    );
}

/// Register `name` through the real `register_agent` tool with a freshly signed,
/// valid proof (used to seed identities when the gate is enabled).
async fn register_with_proof(
    ctx: &McpContext,
    key: &SigningKey,
    project_key: &str,
    name: &str,
    nonce: &str,
) {
    let now = now_unix();
    let proof = signed_proof(
        key,
        name,
        project_key,
        "claude-code",
        "opus-4.1",
        DEFAULT_CAPS,
        now,
        now + 120,
        nonce,
    );
    register_agent(
        ctx,
        project_key.to_string(),
        "claude-code".to_string(),
        "opus-4.1".to_string(),
        Some(name.to_string()),
        Some("valid proof".to_string()),
        None,
        None,
        None,
        Some(proof),
    )
    .await
    .unwrap_or_else(|e| panic!("register {name} with proof: {e:?}"));
}

/// With the gate ENABLED, the two implicit auto-register side doors —
/// `send_message` to an unknown recipient and `request_contact` with an unknown
/// `from_agent` — must FAIL CLOSED and must NOT mint the identity, while
/// resolving already-existing identities keeps working.
#[test]
fn enabled_gate_blocks_send_message_and_request_contact_auto_register() {
    let key = SigningKey::from_bytes(&[21u8; 32]);
    let trusted = b64(key.verifying_key().as_bytes());
    run_with_env(
        &[
            ("AM_REGISTRATION_PROOF_GATE_ENABLED", "true"),
            ("AM_REGISTRATION_PROOF_TRUSTED_KEYS", trusted.as_str()),
        ],
        |cx| async move {
            let ctx = McpContext::new(cx.clone(), 1);
            let project_key = format!("/tmp/proof-autoreg-{}", unique_suffix());
            ensure_project(&ctx, project_key.clone(), None)
                .await
                .expect("ensure_project");

            // A real sender is needed: send_message resolves (never
            // auto-registers) the sender.
            register_with_proof(&ctx, &key, &project_key, "BlueLake", "nonce-a-sender").await;

            // send_message to a NON-existent recipient must fail closed.
            let err = send_message(
                &ctx,
                project_key.clone(),
                "BlueLake".to_string(),
                vec!["GhostRecipient".to_string()],
                "hi".to_string(),
                "body".to_string(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None, // idempotency_key
            )
            .await
            .expect_err("send_message to unknown recipient must fail closed");
            assert_eq!(error_type(&err), "PROOF_REQUIRED");

            // ...and the recipient identity must NOT have been created.
            let err = whois(
                &ctx,
                project_key.clone(),
                "GhostRecipient".to_string(),
                Some(false),
                None,
            )
            .await
            .expect_err("recipient identity must NOT have been created");
            assert_eq!(error_type(&err), "AGENT_NOT_FOUND");

            // request_contact with a NON-existent from_agent (register_if_missing
            // defaults to true) must fail closed.
            let err = request_contact(
                &ctx,
                project_key.clone(),
                "PhantomSender".to_string(),
                "BlueLake".to_string(),
                None,
                Some("hi".to_string()),
                None,
                None,
                Some("claude-code".to_string()),
                Some("opus-4.1".to_string()),
                None,
            )
            .await
            .expect_err("request_contact auto-register must fail closed");
            assert_eq!(error_type(&err), "PROOF_REQUIRED");

            // ...and the from_agent identity must NOT have been created.
            let err = whois(
                &ctx,
                project_key.clone(),
                "PhantomSender".to_string(),
                Some(false),
                None,
            )
            .await
            .expect_err("from_agent identity must NOT have been created");
            assert_eq!(error_type(&err), "AGENT_NOT_FOUND");

            // Existing identities still resolve normally (only the create-on-
            // missing branch is gated): register RedFox with a proof, then a
            // BlueLake -> RedFox message goes through with no auto-registration.
            register_with_proof(&ctx, &key, &project_key, "RedFox", "nonce-a-recip").await;
            send_message(
                &ctx,
                project_key.clone(),
                "BlueLake".to_string(),
                vec!["RedFox".to_string()],
                "hi".to_string(),
                "body".to_string(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(true), // auto_contact_if_blocked
                None,
                None, // idempotency_key
            )
            .await
            .expect("send_message between existing identities should still work");
        },
    );
}

/// With the gate DISABLED (the default), both implicit paths auto-register the
/// missing identity exactly as before — no behavior change.
#[test]
fn disabled_gate_auto_registers_via_send_message_and_request_contact() {
    run_with_env(&[], |cx| async move {
        let ctx = McpContext::new(cx.clone(), 1);
        let project_key = format!("/tmp/proof-off-autoreg-{}", unique_suffix());
        ensure_project(&ctx, project_key.clone(), None)
            .await
            .expect("ensure_project");

        register_agent(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("BlueLake".to_string()),
            Some("gate off".to_string()),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("register sender");

        // send_message auto-registers the unknown recipient.
        send_message(
            &ctx,
            project_key.clone(),
            "BlueLake".to_string(),
            vec!["GreenCastle".to_string()],
            "hi".to_string(),
            "body".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None, // idempotency_key
        )
        .await
        .expect("send_message should auto-register recipient when gate disabled");
        whois(
            &ctx,
            project_key.clone(),
            "GreenCastle".to_string(),
            Some(false),
            None,
        )
        .await
        .expect("AutoRecip should have been auto-registered");

        register_agent(
            &ctx,
            project_key.clone(),
            "claude-code".to_string(),
            "opus-4.1".to_string(),
            Some("RedStone".to_string()),
            Some("gate off".to_string()),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("register target");

        // request_contact auto-registers the unknown from_agent.
        request_contact(
            &ctx,
            project_key.clone(),
            "AmberRiver".to_string(),
            "RedStone".to_string(),
            None,
            Some("hi".to_string()),
            None,
            None,
            Some("claude-code".to_string()),
            Some("opus-4.1".to_string()),
            None,
        )
        .await
        .expect("request_contact should auto-register from_agent when gate disabled");
        whois(
            &ctx,
            project_key.clone(),
            "AmberRiver".to_string(),
            Some(false),
            None,
        )
        .await
        .expect("AutoSender should have been auto-registered");
    });
}
