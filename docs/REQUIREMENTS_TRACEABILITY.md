# ChainForensics — Requirements Traceability Matrix

All functional requirements mapped to implementing file(s) and verifying test(s) across Sprints 1–6.

---

## Sprint 1 — Detection Engine

| ID | Requirement | Implementing File(s) | Verifying Test(s) |
|---|---|---|---|
| S1-01 | Load CICIDS-2017 CSV with label normalization | `chainforensics/ingestion.py` `load_csv()` | `test_sprint6_business_logic.py::test_load_csv_normalizes_columns_labels_and_rejects_unknown` |
| S1-02 | Reject rows with unsupported labels (not BENIGN/DoS/PortScan/BruteForce) | `chainforensics/ingestion.py` `_normalize_labels()` | `test_sprint6_business_logic.py::test_load_csv_normalizes_columns_labels_and_rejects_unknown` |
| S1-03 | Map CICIDS raw labels to canonical classes (e.g., "DoS Hulk" → "DoS") | `chainforensics/ingestion.py` `CICIDS_LABEL_MAP` | `test_sprint6_business_logic.py::test_load_csv_maps_cicids_labels` |
| S1-04 | Validate and clean 78-column feature contract | `chainforensics/features.py` `FeatureCleaner` | `test_sprint6_business_logic.py::test_feature_cleaner_repairs_nan_inf_and_negative_duration` |
| S1-05 | Repair NaN/Inf/negative Duration values using training medians | `chainforensics/features.py` `FeatureCleaner.fit_transform()` | `test_sprint6_business_logic.py::test_feature_cleaner_repairs_nan_inf_and_negative_duration` |
| S1-06 | Train RandomForest and persist artifact with version metadata | `chainforensics/model.py` `train_and_persist()` | `test_sprint6_business_logic.py::test_train_load_and_predict_real_model` |
| S1-07 | Load persisted detector and validate schema version | `chainforensics/model.py` `load_detector()` | `test_sprint6_business_logic.py::test_load_detector_rejects_invalid_artifact` |
| S1-08 | Run inference and return label + class probabilities | `chainforensics/model.py` `predict()` | `test_sprint6_business_logic.py::test_train_load_and_predict_real_model` |
| S1-09 | Reject non-DataFrame inference input | `chainforensics/model.py` `predict()` | `test_sprint6_business_logic.py::test_predict_rejects_non_dataframe` |
| S1-10 | Reject wrong feature column contract at inference | `chainforensics/model.py` `predict()` | `test_sprint6_business_logic.py::test_predict_rejects_wrong_feature_contract` |

---

## Sprint 2 — Blockchain Ledger & Smart Contract

| ID | Requirement | Implementing File(s) | Verifying Test(s) |
|---|---|---|---|
| S2-01 | Build deterministic canonical forensic event | `chainforensics/event_builder.py` `build_forensic_event()` | `test_event_builder.py::test_hash_is_deterministic_regardless_of_dict_order` |
| S2-02 | Produce SHA-256 hash of forensic event | `chainforensics/event_builder.py` `hash_forensic_event()` | `test_event_builder.py::test_hash_is_deterministic_regardless_of_dict_order` |
| S2-03 | Write event hash synchronously to ForensicLedger | `chainforensics/blockchain/client.py` `log_event()` | `test_blockchain_local.py::test_python_client_local_hardhat_round_trip` |
| S2-04 | Smart contract rejects empty hash | `contracts/ForensicLedger.sol` `logEvent()` | `test/ForensicLedger.test.js::rejects an empty hash` |
| S2-05 | Smart contract rejects duplicate hash | `contracts/ForensicLedger.sol` `hashExists mapping` | `test/ForensicLedger.test.js::rejects duplicate event hashes`, `test_blockchain_duplicate.py` |
| S2-06 | Smart contract validates index on reads | `contracts/ForensicLedger.sol` `validIndex modifier` | `test/ForensicLedger.test.js::rejects out-of-range reads` |
| S2-07 | Smart contract emits EventLogged event | `contracts/ForensicLedger.sol` `emit EventLogged` | `test/ForensicLedger.test.js::logs a valid event and reads it back` |
| S2-08 | Blockchain client retries with exponential backoff | `chainforensics/blockchain/client.py` `_with_retry()` | `test_blockchain_retry.py::test_rpc_retry_backoff` |
| S2-09 | Load ABI from compiled Hardhat artifact | `chainforensics/blockchain/abi.py` `load_forensic_ledger_abi()` | Implicit in all blockchain integration tests |

---

## Sprint 3 — Explainability & Recovery Recommendations

| ID | Requirement | Implementing File(s) | Verifying Test(s) |
|---|---|---|---|
| S3-01 | Generate human-readable explanation for known attack types | `chainforensics/explainability/generator.py` `generate_explanation()` | `test_explainability.py::test_all_supported_attack_types_generate_output` |
| S3-02 | Explanation contains real event values (IP, port, confidence) | `chainforensics/explainability/generator.py` `_template_values()` | `test_explainability.py::test_generated_explanation_contains_real_event_values` |
| S3-03 | Recovery recommendations contain real event values | `chainforensics/explainability/knowledge_base.py` templates | `test_explainability.py::test_recovery_recommendations_contain_real_values` |
| S3-04 | Unknown attack types return manual_review_required (no exception) | `chainforensics/explainability/generator.py` L76–96 | `test_explainability.py::test_unknown_attack_type_uses_manual_review_fallback` |
| S3-05 | New attack type (SQLInjection) added without modifying generator | `chainforensics/explainability/knowledge_base.py` L130–147 | `test_explainability.py::test_sql_injection_demonstration_attack_type` |
| S3-06 | Existing attack types unaffected by knowledge base extension | `chainforensics/explainability/knowledge_base.py` | `test_explainability.py::test_existing_attack_types_remain_supported_after_extension` |
| S3-07 | Full sprint 3 pipeline: event → explanation | `ingestion`, `model`, `event_builder`, `generator` | `test_sprint3_integration.py::test_real_sprint_pipeline_event_to_explanation` |

---

## Sprint 4 — Recovery Simulator & Verifier

| ID | Requirement | Implementing File(s) | Verifying Test(s) |
|---|---|---|---|
| S4-01 | BENIGN events always simulate as verified | `chainforensics/recovery/simulator.py` L102–111 | `test_sprint6_business_logic.py::test_recovery_benign_is_verified` |
| S4-02 | Deterministic threshold rules per attack type | `chainforensics/recovery/simulator.py` | `test_sprint6_business_logic.py::test_recovery_threshold_rules` (8 parametrized cases) |
| S4-03 | Missing required feature escalates (not crashes) | `chainforensics/recovery/simulator.py` `_numeric_feature()` | `test_sprint6_business_logic.py::test_recovery_missing_required_feature_escalates` |
| S4-04 | Boolean treated as missing (not numeric) | `chainforensics/recovery/simulator.py` `_numeric_feature()` L46–47 | `test_sprint6_business_logic.py::test_recovery_rejects_boolean_as_numeric_feature` |
| S4-05 | Unknown attack type escalates to manual review | `chainforensics/recovery/simulator.py` L287–295 | `test_sprint6_business_logic.py::test_unknown_attack_type_requires_manual_review` |
| S4-06 | Verified recovery calls mark_recovery_verified exactly once | `chainforensics/recovery/verifier.py` `verify_recovery()` | `test_recovery.py::test_verified_success_calls_mark_recovery_verified_once` |
| S4-07 | find_event_index scans chain by hash (not by assumed index) | `chainforensics/recovery/verifier.py` `find_event_index()` | `test_recovery.py::test_find_event_index_scans_actual_chain` |
| S4-08 | find_event_index returns None when hash not on chain | `chainforensics/recovery/verifier.py` `find_event_index()` | `test_recovery.py::test_find_event_index_returns_none_when_missing` |
| S4-09 | Escalated recovery produces NO blockchain write | `chainforensics/recovery/verifier.py` L125–140 | `test_recovery.py::test_escalated_failure_does_not_write_blockchain` |
| S4-10 | Only owner can call markRecoveryVerified on-chain | `contracts/ForensicLedger.sol` `onlyOwner` modifier | `test/ForensicLedger.test.js::rejects recovery verification from a non-owner` |
| S4-11 | Full closed-loop: detect → blockchain → explain → recover → verify | All pipeline modules | `test_sprint6_e2e_pipeline.py::TestEndToEndPipeline::test_full_pipeline_dos_attack_verified` |

---

## Sprint 5 — API, Database & BASE Metrics

| ID | Requirement | Implementing File(s) | Verifying Test(s) |
|---|---|---|---|
| S5-01 | Persist forensic incident to SQLite | `chainforensics/database/repository.py` `create_incident()` | `test_database_repository.py::test_real_incident_persistence` |
| S5-02 | Update incident with blockchain result | `chainforensics/database/repository.py` `update_blockchain_result()` | `test_database_repository.py::test_real_incident_persistence` |
| S5-03 | Update incident with recovery result | `chainforensics/database/repository.py` `update_recovery_result()` | `test_database_repository.py::test_real_incident_persistence` |
| S5-04 | Query incidents with optional filters | `chainforensics/database/repository.py` `list_incidents()` | `test_database_repository.py::test_incident_filtering` |
| S5-05 | GET /health returns 200 (unauthenticated) | `chainforensics/api/main.py` `/health` route | `test_sprint6_e2e_pipeline.py::TestAPIEndToEnd::test_api_health_and_incidents` |
| S5-06 | GET /incidents requires API key | `chainforensics/api/dependencies.py` `require_api_key()` | `test_sprint6_coverage_gaps.py::TestDependenciesAuth::test_missing_api_key_header_returns_401` |
| S5-07 | GET /incidents returns paginated incident list | `chainforensics/api/incidents.py` `get_incidents()` | `test_sprint6_e2e_pipeline.py::TestAPIEndToEnd::test_api_health_and_incidents` |
| S5-08 | GET /incidents/{hash} returns single incident | `chainforensics/api/incidents.py` `get_incident_by_hash()` | `test_sprint6_e2e_pipeline.py::TestAPIEndToEnd::test_api_health_and_incidents` |
| S5-09 | 404 for missing incident hash | `chainforensics/api/incidents.py` L158–163 | `test_sprint6_e2e_pipeline.py::TestAPIEndToEnd::test_api_health_and_incidents` |
| S5-10 | POST /incidents/detect — full off-chain pipeline | `chainforensics/api/incidents.py` `process_traffic_detection()` | `test_sprint6_coverage_gaps.py::TestDetectEndpointCoverage::test_detect_new_incident_no_blockchain` |
| S5-11 | POST /incidents/detect — idempotent duplicate handling | `chainforensics/api/incidents.py` L192–194 | `test_sprint6_coverage_gaps.py::TestDetectEndpointCoverage::test_detect_duplicate_returns_cached` |
| S5-12 | POST /incidents/detect — blockchain write + graceful failure | `chainforensics/api/incidents.py` L206–236 | `test_sprint6_coverage_gaps.py::TestDetectEndpointCoverage::test_detect_with_mocked_blockchain_write` |
| S5-13 | GET /metrics BASE framework metrics via API | `chainforensics/api/main.py` `/metrics` route | `test_sprint6_e2e_pipeline.py::TestAPIEndToEnd::test_api_health_and_incidents` |
| S5-14 | API key comparison is constant-time | `chainforensics/api/dependencies.py` `secrets.compare_digest()` | `test_sprint6_coverage_gaps.py::TestDependenciesAuth::test_wrong_api_key_returns_401` |
| S5-15 | No stack traces returned to API callers | `chainforensics/api/errors.py` `generic_exception_handler()` | `test_sprint6_coverage_gaps.py::TestErrorsModule::test_api_unhandled_exception_returns_500_not_traceback` |

---

## Sprint 6 — Hardening, Security, Documentation

| ID | Requirement | Implementing File(s) | Verifying Test(s) |
|---|---|---|---|
| S6-01 | Full regression test suite runs in one pass (117 tests) | All test files in `tests/` | **117 passed, 0 failed** — 2026-09-30 |
| S6-02 | End-to-end pipeline test (detect→blockchain→explain→recover→verify→persist→API) | `tests/test_sprint6_e2e_pipeline.py` | 5 E2E tests: `test_full_pipeline_dos_attack_verified`, `test_full_pipeline_portscan_escalated`, `test_full_pipeline_benign_event`, `test_full_pipeline_unknown_attack_manual_review`, `test_api_health_and_incidents` |
| S6-03 | Honest threat model with Sepolia deployment documented | `SECURITY.md` | Security review |
| S6-04 | Full architecture documentation with pillar traceability | `ARCHITECTURE.md` | Documentation review |
| S6-05 | Setup guide (SETUP.md) for brand-new engineer | `docs/SETUP.md` | Walkthrough mentally verified |
| S6-06 | Complete API reference with all endpoints | `docs/API_REFERENCE.md` | Documentation covers all 8 routes |
| S6-07 | Evaluation report with real final numbers | `docs/EVALUATION_REPORT.md` | Real numbers: 117 tests, 85% coverage, Sepolia gas/latency |
| S6-08 | GitHub Actions CI workflow (lint + test + contract) | `.github/workflows/ci.yml` | YAML verified, --cov-fail-under=80 gate added |
| S6-09 | Requirements traceability matrix | `docs/REQUIREMENTS_TRACEABILITY.md` | This document |
| S6-10 | Known Limitations (honest, production-vendor-grade) | `docs/KNOWN_LIMITATIONS.md` | 9 limitations documented |
| S6-11 | Coverage ≥80% for all business-logic modules | `tests/test_sprint6_coverage_gaps.py` | 18 targeted gap tests; final total: **85%** |
| S6-12 | Dashboard data endpoints covered by tests | `tests/test_sprint6_coverage_gaps.py` | `TestDashboardStats::test_dashboard_stats_no_auth_required`, `test_dashboard_stats_with_incidents`, `test_dashboard_html_root_returns_200` |
| S6-13 | Final honest summary paragraph | `docs/FINAL_SUMMARY.md` | One-paragraph summary of what this system is |
| S6-14 | SETUP.md updated for Sepolia (not Hardhat) deployment | `docs/SETUP.md` | Sepolia steps documented |
| S6-15 | Load test with honest findings documented | `load_test_detect.py`, `load_test_report.json` | `load_test_report.json` written with disclaimer |
