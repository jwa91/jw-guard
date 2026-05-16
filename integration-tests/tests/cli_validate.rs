use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn run_cli(args: &[&str], stdout_is_tty: bool) -> (i32, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut argv = Vec::<OsString>::with_capacity(args.len() + 1);
    argv.push(OsString::from("jw-guard"));
    argv.extend(args.iter().map(OsString::from));
    let code = jw_guard_cli::run(argv, stdout_is_tty, &mut stdout, &mut stderr);
    let stdout_text = String::from_utf8(stdout).expect("stdout should be utf-8");
    let stderr_text = String::from_utf8(stderr).expect("stderr should be utf-8");
    (code, stdout_text, stderr_text)
}

fn write_temp(content: &str, extension: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be valid")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("jw_guard_cli_test_{now}.{extension}"));
    fs::write(&path, content).expect("should write temp file");
    path
}

fn parse_report(stdout: &str) -> Value {
    serde_json::from_str(stdout).expect("json report should parse")
}

fn normalize_path(report: &mut Value) {
    report["input"]["path"] = Value::String("__PATH__".to_owned());
}

fn assert_matches_fixture(mut report: Value, fixture: &str) {
    normalize_path(&mut report);
    let expected: Value = serde_json::from_str(fixture).expect("fixture should parse");
    assert_eq!(report, expected);
}

#[test]
fn validate_defaults_to_json_output_when_stdout_not_tty() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");
    let path = write_temp(fixture, "json");
    let path_text = path.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_cli(&["validate", &path_text], false);
    let _ = fs::remove_file(path);

    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    let report: Value = parse_report(&stdout);
    assert_eq!(report["report_version"], "1");
    assert_eq!(report["outcome"], "ok");
    assert_eq!(report["stage_reached"], "concretise");
    assert!(stdout.starts_with("{\n  \"report_version\""));
}

#[test]
fn validate_emits_syntax_error_report_for_invalid_json() {
    let path = write_temp("{", "json");
    let path_text = path.to_string_lossy().to_string();
    let (code, stdout, _) = run_cli(&["validate", &path_text, "--output", "json"], false);
    let _ = fs::remove_file(path);

    assert_eq!(code, 1);
    let report: Value = parse_report(&stdout);
    assert_matches_fixture(report, include_str!("fixtures/reports/syntax_error.json"));
}

#[test]
fn validate_emits_wire_error_for_unknown_field() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");
    let broken = fixture.replacen(
        "\"policies\": [",
        "\"unknown_root\": true,\n  \"policies\": [",
        1,
    );
    let path = write_temp(&broken, "json");
    let path_text = path.to_string_lossy().to_string();
    let (code, stdout, _) = run_cli(&["validate", &path_text, "--output", "json"], false);
    let _ = fs::remove_file(path);

    assert_eq!(code, 1);
    let report: Value = parse_report(&stdout);
    assert_matches_fixture(report, include_str!("fixtures/reports/wire_error.json"));
}

#[test]
fn validate_emits_validation_error_for_missing_reference() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");
    let broken = fixture.replacen("\"declared_by\": \"owner\"", "\"declared_by\": \"ghost\"", 1);
    let path = write_temp(&broken, "json");
    let path_text = path.to_string_lossy().to_string();
    let (code, stdout, _) = run_cli(&["validate", &path_text, "--output", "json"], false);
    let _ = fs::remove_file(path);

    assert_eq!(code, 1);
    let report: Value = parse_report(&stdout);
    assert_matches_fixture(report, include_str!("fixtures/reports/validation_error.json"));
}

#[test]
fn validate_respects_stage_short_circuit() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");
    let broken = fixture.replacen("\"declared_by\": \"owner\"", "\"declared_by\": \"ghost\"", 1);
    let path = write_temp(&broken, "json");
    let path_text = path.to_string_lossy().to_string();
    let (code, stdout, _) = run_cli(
        &["validate", &path_text, "--stage", "wire", "--output", "json"],
        false,
    );
    let _ = fs::remove_file(path);

    assert_eq!(code, 0);
    let report: Value = serde_json::from_str(&stdout).expect("json report should parse");
    assert_eq!(report["outcome"], "ok");
    assert_eq!(report["stage_reached"], "wire");
}

#[test]
fn validate_defaults_to_human_output_when_stdout_is_tty() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");
    let path = write_temp(fixture, "json");
    let path_text = path.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_cli(&["validate", &path_text], true);
    let _ = fs::remove_file(path);

    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.contains("ok:"));
}

#[test]
fn output_channel_discipline_is_enforced_for_failures() {
    let bad_json = write_temp("{", "json");
    let bad_path = bad_json.to_string_lossy().to_string();

    let (_json_code, json_stdout, json_stderr) =
        run_cli(&["validate", &bad_path, "--output", "json"], false);
    assert!(!json_stdout.is_empty());
    assert!(json_stderr.is_empty());

    let (_human_code, human_stdout, human_stderr) =
        run_cli(&["validate", &bad_path, "--output", "human"], false);
    assert!(human_stdout.is_empty());
    assert!(!human_stderr.is_empty());

    let _ = fs::remove_file(bad_json);
}

#[test]
fn source_availability_matches_stage_contract() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");

    let wire_input = fixture.replacen(
        "\"policies\": [",
        "\"unknown_root\": true,\n  \"policies\": [",
        1,
    );
    let wire_path = write_temp(&wire_input, "json");
    let wire_path_text = wire_path.to_string_lossy().to_string();
    let (_code, wire_stdout, _stderr) = run_cli(&["validate", &wire_path_text, "--output", "json"], false);
    let wire_report = parse_report(&wire_stdout);
    assert!(wire_report["errors"][0]["source"].is_object());
    let _ = fs::remove_file(wire_path);

    let yaml_wire_input = include_str!("../../docs/examples/declared_spec.example.yaml").replacen(
        "policies:",
        "unknown_root: true\npolicies:",
        1,
    );
    let yaml_wire_path = write_temp(&yaml_wire_input, "yaml");
    let yaml_wire_path_text = yaml_wire_path.to_string_lossy().to_string();
    let (_code, yaml_wire_stdout, _stderr) =
        run_cli(&["validate", &yaml_wire_path_text, "--output", "json"], false);
    let yaml_wire_report = parse_report(&yaml_wire_stdout);
    assert!(yaml_wire_report["errors"][0]["source"].is_object());
    let _ = fs::remove_file(yaml_wire_path);

    let validation_input = fixture.replacen("\"declared_by\": \"owner\"", "\"declared_by\": \"ghost\"", 1);
    let validation_path = write_temp(&validation_input, "json");
    let validation_path_text = validation_path.to_string_lossy().to_string();
    let (_code, validation_stdout, _stderr) =
        run_cli(&["validate", &validation_path_text, "--output", "json"], false);
    let validation_report = parse_report(&validation_stdout);
    assert!(validation_report["errors"][0]["source"].is_null());
    let _ = fs::remove_file(validation_path);
}

#[test]
fn validation_multi_error_output_is_deterministic_and_sorted() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");
    let broken = fixture
        .replacen("\"declared_by\": \"owner\"", "\"declared_by\": \"ghost_actor\"", 1)
        .replacen("\"declared_by\": \"owner\"", "\"declared_by\": \"ghost_actor\"", 1)
        .replacen("\"scope\": \"external\"", "\"scope\": \"ghost_scope\"", 1)
        .replacen("\"requirement\": \"minimum\"", "\"requirement\": \"ghost_requirement\"", 1);
    let path = write_temp(&broken, "json");
    let path_text = path.to_string_lossy().to_string();

    let (_code_a, stdout_a, _stderr_a) = run_cli(&["validate", &path_text, "--output", "json"], false);
    let (_code_b, stdout_b, _stderr_b) = run_cli(&["validate", &path_text, "--output", "json"], false);
    let _ = fs::remove_file(path);

    assert_eq!(stdout_a, stdout_b);

    let report = parse_report(&stdout_a);
    assert_matches_fixture(report, include_str!("fixtures/reports/validation_multi_error.json"));
}

#[test]
fn wire_path_segments_keep_numeric_indices() {
    let fixture = include_str!("../../docs/examples/declared_spec.example.json");
    let broken = fixture.replacen("\"name\": \"external\"", "\"name\": \"InvalidScope\"", 1);
    let path = write_temp(&broken, "json");
    let path_text = path.to_string_lossy().to_string();

    let (_code, stdout, _stderr) = run_cli(&["validate", &path_text, "--output", "json"], false);
    let _ = fs::remove_file(path);

    let report = parse_report(&stdout);
    let path_segments = report["errors"][0]["path"]
        .as_array()
        .expect("path must be an array");
    assert!(path_segments[1].is_number());
}

#[test]
fn schema_emit_is_deterministic() {
    let (first_code, first_stdout, first_stderr) = run_cli(&["schema", "emit"], false);
    let (second_code, second_stdout, second_stderr) = run_cli(&["schema", "emit"], false);

    assert_eq!(first_code, 0);
    assert_eq!(second_code, 0);
    assert!(first_stderr.is_empty());
    assert!(second_stderr.is_empty());
    assert_eq!(first_stdout, second_stdout);
}

#[test]
fn validate_returns_io_exit_code_for_missing_file() {
    let (code, _stdout, stderr) = run_cli(
        &[
            "validate",
            "/tmp/jw_guard_does_not_exist_123456789.json",
            "--output",
            "json",
        ],
        false,
    );
    assert_eq!(code, 3);
    assert!(stderr.contains("i/o error"));
}

#[test]
fn evaluate_docker_compose_reports_property_violation_without_enforcing_exit_failure() {
    let compose = r#"
services:
  web:
    image: nginx
    privileged: true
"#;
    let path = write_temp(compose, "yaml");
    let path_text = path.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_cli(
        &[
            "evaluate",
            "docker-compose",
            "--compose",
            &path_text,
            "--subject",
            "web",
            "--property",
            "privileged",
            "--expect-bool",
            "false",
            "--output",
            "json",
        ],
        false,
    );
    let _ = fs::remove_file(path);

    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    let report: Value = parse_report(&stdout);
    assert_eq!(report["kind"], "docker_compose_property");
    assert_eq!(report["subject"], "web");
    assert_eq!(report["property"], "privileged");
    assert_eq!(report["expected_bool"], false);
    assert_eq!(report["outcome"], "violated");
    assert_eq!(report["reason"], "property_violated");
}

#[test]
fn evaluate_docker_compose_accepts_declared_policy_file() {
    let compose = r#"
services:
  web:
    image: nginx
    privileged: true
"#;
    let policy = r#"
property_requirements:
  - subject: web
    property: privileged
    expected_bool: false
"#;
    let compose_path = write_temp(compose, "yaml");
    let policy_path = write_temp(policy, "yaml");
    let compose_text = compose_path.to_string_lossy().to_string();
    let policy_text = policy_path.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_cli(
        &[
            "evaluate",
            "docker-compose",
            "--compose",
            &compose_text,
            "--policy",
            &policy_text,
            "--output",
            "json",
        ],
        false,
    );
    let _ = fs::remove_file(compose_path);
    let _ = fs::remove_file(policy_path);

    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    let report: Value = parse_report(&stdout);
    assert_eq!(report["kind"], "docker_compose_property");
    assert_eq!(report["subject"], "web");
    assert_eq!(report["property"], "privileged");
    assert_eq!(report["expected_bool"], false);
    assert_eq!(report["outcome"], "violated");
    assert_eq!(report["reason"], "property_violated");
}
