# Build verification report

Build date: September 19, 2026.

## Environment

- Linux container; Python 3.13.5; Node.js v22.16.0.
- No target harness binaries were launched for end-to-end verification.
- No TypeSafe credentials were supplied and no live Jev API calls were made.
- No installation was performed on the user's machine, servers or accounts.

## Results

**66 Python tests passed. Nine JavaScript tests passed.**

The Python suite covers deterministic routing, taint/profile isolation, explicit
remote consent, mocked Noul response validation, request budgets, redaction,
metadata-only audit records, native JSON hook contracts, subprocess watchdog
behavior, malformed and oversized input, nine-target installation into temporary
profiles, configuration preservation, idempotence, backups, uninstall conflicts,
symlink refusal, command quoting and simulated Hermes native enable/rollback.
The Hermes plugin adapter also invokes the real local Python evaluator in tests.

JavaScript tests simulate callback dispatch for OpenCode, Pi and OpenClaw. The
OpenClaw definePluginEntry loader is stubbed: the actual SDK is not installed.
They verify the adapter's callback behavior plus one real Node-to-Python process
bridge. Native host ordering, plugin loading, binary-version compatibility,
real-host hook trust and platform-specific dispatch remain unverified.

An offline RAG demonstration also ran: one benign passage was retained and one
injection-looking passage was quarantined using local rules. This is a plumbing
demonstration, not an accuracy benchmark. No AgentDojo, adaptive attack suite,
live Jev classification benchmark or penetration test was performed.

Windows shell construction is unit-tested, but native Windows/macOS execution was
not performed. The included cross-platform CI workflow is a recipe, not evidence
of completed CI runs. Runtime/model performance and latency are not benchmarked.

## Python test output

```text
test_audit_does_not_record_content_or_arguments (test_core.CoreTests.test_audit_does_not_record_content_or_arguments) ... ok
test_canary_blocks (test_core.CoreTests.test_canary_blocks) ... ok
test_clean_defer_is_not_authorization (test_core.CoreTests.test_clean_defer_is_not_authorization) ... ok
test_content_limit_not_silent_truncation (test_core.CoreTests.test_content_limit_not_silent_truncation) ... ok
test_denied_tool_cannot_be_overridden (test_core.CoreTests.test_denied_tool_cannot_be_overridden) ... ok
test_external_instruction_quarantined (test_core.CoreTests.test_external_instruction_quarantined) ... ok
test_goal_question_only_when_goal_known (test_core.CoreTests.test_goal_question_only_when_goal_known) ... ok
test_input_unknown_fields_rejected (test_core.CoreTests.test_input_unknown_fields_rejected) ... ok
test_large_goal_is_unknown_not_truncated_authority (test_core.CoreTests.test_large_goal_is_unknown_not_truncated_authority) ... ok
test_local_scores_are_not_fabricated (test_core.CoreTests.test_local_scores_are_not_fabricated) ... ok
test_missing_session_does_not_taint_other_users (test_core.CoreTests.test_missing_session_does_not_taint_other_users) ... ok
test_new_user_goal_does_not_clear_taint (test_core.CoreTests.test_new_user_goal_does_not_clear_taint) ... ok
test_no_remote_without_consent (test_core.CoreTests.test_no_remote_without_consent) ... ok
test_policy_rejects_unknown_fields_and_bool_threshold (test_core.CoreTests.test_policy_rejects_unknown_fields_and_bool_threshold) ... ok
test_profiles_do_not_share_latches (test_core.CoreTests.test_profiles_do_not_share_latches) ... ok
test_readonly_exception_is_explicit (test_core.CoreTests.test_readonly_exception_is_explicit) ... ok
test_remote_budget_restricts_calls (test_core.CoreTests.test_remote_budget_restricts_calls) ... ok
test_remote_failure_never_erases_local_finding (test_core.CoreTests.test_remote_failure_never_erases_local_finding) ... ok
test_remote_high_block (test_core.CoreTests.test_remote_high_block) ... ok
test_remote_high_external_quarantine (test_core.CoreTests.test_remote_high_external_quarantine) ... ok
test_remote_low_defer (test_core.CoreTests.test_remote_low_defer) ... ok
test_remote_middle_review (test_core.CoreTests.test_remote_middle_review) ... ok
test_remote_missing_answer_review (test_core.CoreTests.test_remote_missing_answer_review) ... ok
test_remote_out_of_range_and_boolean_rejected (test_core.CoreTests.test_remote_out_of_range_and_boolean_rejected) ... ok
test_remote_redaction_preserves_json (test_core.CoreTests.test_remote_redaction_preserves_json) ... ok
test_remote_wrong_answer_shape_review (test_core.CoreTests.test_remote_wrong_answer_shape_review) ... ok
test_required_unknown_goal_review (test_core.CoreTests.test_required_unknown_goal_review) ... ok
test_secret_transfer_example (test_core.CoreTests.test_secret_transfer_example) ... ok
test_shadow_records_without_enforcing (test_core.CoreTests.test_shadow_records_without_enforcing) ... ok
test_strict_json_rejects_duplicates_and_nan (test_core.CoreTests.test_strict_json_rejects_duplicates_and_nan) ... ok
test_taint_latches_sensitive_tool (test_core.CoreTests.test_taint_latches_sensitive_tool) ... ok
test_untrusted_memory_never_authorized_by_model (test_core.CoreTests.test_untrusted_memory_never_authorized_by_model) ... ok
test_actual_cli_native_canary_and_malformed_json (test_hooks.HookTests.test_actual_cli_native_canary_and_malformed_json) ... ok
test_claude_bash_replacement_requires_known_shape (test_hooks.HookTests.test_claude_bash_replacement_requires_known_shape) ... ok
test_claude_mcp_result_can_be_replaced (test_hooks.HookTests.test_claude_mcp_result_can_be_replaced) ... ok
test_cli_oversize_input_is_review (test_hooks.HookTests.test_cli_oversize_input_is_review) ... ok
test_codex_does_not_receive_unsupported_fields (test_hooks.HookTests.test_codex_does_not_receive_unsupported_fields) ... ok
test_copilot_string_tool_args_decoded (test_hooks.HookTests.test_copilot_string_tool_args_decoded) ... ok
test_defer_preserves_other_native_authorization (test_hooks.HookTests.test_defer_preserves_other_native_authorization) ... ok
test_ingress_payload_cannot_override_provenance (test_hooks.HookTests.test_ingress_payload_cannot_override_provenance) ... ok
test_missing_result_is_error_not_clean (test_hooks.HookTests.test_missing_result_is_error_not_clean) ... ok
test_native_pretool_veto_shapes (test_hooks.HookTests.test_native_pretool_veto_shapes) ... ok
test_observer_returns_no_fake_veto (test_hooks.HookTests.test_observer_returns_no_fake_veto) ... ok
test_process_watchdog_timeout_returns_review (test_hooks.HookTests.test_process_watchdog_timeout_returns_review) ... ok
test_all_nine_installed_and_policy_local_shadow (test_installer.InstallerTests.test_all_nine_installed_and_policy_local_shadow) ... ok
test_detect_only_existing_roots (test_installer.InstallerTests.test_detect_only_existing_roots) ... ok
test_distinct_profiles_are_independently_installed (test_installer.InstallerTests.test_distinct_profiles_are_independently_installed) ... ok
test_gemini_milliseconds_and_copilot_direct_exec (test_installer.InstallerTests.test_gemini_milliseconds_and_copilot_direct_exec) ... ok
test_idempotent_no_duplicate_hooks (test_installer.InstallerTests.test_idempotent_no_duplicate_hooks) ... ok
test_installed_hook_command_executes_without_source_cwd (test_installer.InstallerTests.test_installed_hook_command_executes_without_source_cwd) ... ok
test_interrupted_journal_is_preserved (test_installer.InstallerTests.test_interrupted_journal_is_preserved) ... ok
test_json5_refused_without_writes (test_installer.InstallerTests.test_json5_refused_without_writes) ... ok
test_native_enable_failure_rolls_back_files (test_installer.InstallerTests.test_native_enable_failure_rolls_back_files) ... ok
test_native_enable_success_is_backed_up (test_installer.InstallerTests.test_native_enable_success_is_backed_up) ... ok
test_openclaw_preserves_allowlist_and_disable (test_installer.InstallerTests.test_openclaw_preserves_allowlist_and_disable) ... ok
test_operator_policy_is_retained_across_reinstall_uninstall (test_installer.InstallerTests.test_operator_policy_is_retained_across_reinstall_uninstall) ... ok
test_plan_is_read_only (test_installer.InstallerTests.test_plan_is_read_only) ... ok
test_posix_paths_with_spaces_are_quoted (test_installer.InstallerTests.test_posix_paths_with_spaces_are_quoted) ... ok
test_preserve_existing_native_settings_and_hooks (test_installer.InstallerTests.test_preserve_existing_native_settings_and_hooks) ... ok
test_symlink_destination_rejected (test_installer.InstallerTests.test_symlink_destination_rejected) ... ok
test_uninstall_conflict_makes_no_changes (test_installer.InstallerTests.test_uninstall_conflict_makes_no_changes) ... ok
test_uninstall_restores_exact_original_bytes (test_installer.InstallerTests.test_uninstall_restores_exact_original_bytes) ... ok
test_windows_quoting_and_metacharacter_refusal (test_installer.InstallerTests.test_windows_quoting_and_metacharacter_refusal) ... ok
test_real_posttool_observation_latches_next_action (test_plugin_python.HermesAdapterTests.test_real_posttool_observation_latches_next_action) ... ok
test_real_pretool_canary_returns_block (test_plugin_python.HermesAdapterTests.test_real_pretool_canary_returns_block) ... ok
test_register_contract (test_plugin_python.HermesAdapterTests.test_register_contract) ... ok

----------------------------------------------------------------------
Ran 66 tests in 7.095s

OK
```

## JavaScript test output

```text
TAP version 13
# Subtest: OpenCode before hook throws on veto, preserving arguments
ok 1 - OpenCode before hook throws on veto, preserving arguments
  ---
  duration_ms: 5.836964
  type: 'test'
  ...
# Subtest: OpenCode after hook replaces output and metadata
ok 2 - OpenCode after hook replaces output and metadata
  ---
  duration_ms: 3.052392
  type: 'test'
  ...
# Subtest: OpenCode DEFER does not mutate a tool result
ok 3 - OpenCode DEFER does not mutate a tool result
  ---
  duration_ms: 2.098294
  type: 'test'
  ...
# Subtest: Pi intercepts user ingress but not extension-generated input
ok 4 - Pi intercepts user ingress but not extension-generated input
  ---
  duration_ms: 4.309246
  type: 'test'
  ...
# Subtest: Pi tool_call uses a block directive
ok 5 - Pi tool_call uses a block directive
  ---
  duration_ms: 1.667388
  type: 'test'
  ...
# Subtest: Pi tool_result replaces content and details
ok 6 - Pi tool_result replaces content and details
  ---
  duration_ms: 2.460576
  type: 'test'
  ...
# Subtest: OpenClaw registers a pre-tool veto with the documented shape
ok 7 - OpenClaw registers a pre-tool veto with the documented shape
  ---
  duration_ms: 1.719555
  type: 'test'
  ...
# Subtest: OpenClaw after-tool handler is explicitly an observer
ok 8 - OpenClaw after-tool handler is explicitly an observer
  ---
  duration_ms: 1.974779
  type: 'test'
  ...
# Subtest: Actual Node-to-Python subprocess bridge returns an enforced canary veto
ok 9 - Actual Node-to-Python subprocess bridge returns an enforced canary veto
  ---
  duration_ms: 1773.224453
  type: 'test'
  ...
1..9
# tests 9
# suites 0
# pass 9
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 1850.923022
```
