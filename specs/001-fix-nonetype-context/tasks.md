# Tasks: Fix NoneType Context Manager Error in VoiceFlow Transcription

**Input**: Design documents from `/specs/001-fix-nonetype-context/`
**Prerequisites**: plan.md (✅), research.md (✅), data-model.md (✅), contracts/ (✅), quickstart.md (✅)

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- Include exact file paths in descriptions

## Phase 3.1: Setup & Environment
- [x] T001 Verify current VoiceFlow installation and dependencies are working
- [x] T002 Create backup of src/voiceflow/core/asr_buffer_safe.py before modifications
- [x] T003 [P] Run baseline tests to document current failure patterns
- [ ] T004 [P] Configure enhanced logging for model state tracking

## Phase 3.2: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE 3.3
**CRITICAL: These tests MUST be written and MUST FAIL before ANY implementation**

### Model Safety Contract Tests
- [ ] T005 [P] Contract test for SafeModelInterface.get_safe_context() in tests/unit/test_safe_model_contract.py
- [ ] T006 [P] Contract test for SafeModelInterface.transcribe_safely() in tests/unit/test_transcription_contract.py
- [ ] T007 [P] Contract test for SafeModelInterface.reload_model_atomically() in tests/unit/test_reload_contract.py
- [ ] T008 [P] Contract test for ErrorRecoveryInterface.attempt_recovery() in tests/unit/test_recovery_contract.py

### Integration Scenario Tests
- [ ] T009 [P] Integration test: consecutive transcriptions (1-10) in tests/integration/test_consecutive_transcriptions.py
- [ ] T010 [P] Integration test: model reload failure scenarios in tests/integration/test_reload_failures.py
- [ ] T011 [P] Integration test: NoneType error reproduction in tests/integration/test_nonetype_reproduction.py
- [ ] T012 [P] Integration test: extended session stability in tests/integration/test_extended_stability.py

### Stress and Edge Case Tests
- [ ] T013 [P] Stress test: rapid transcription requests in tests/stress/test_rapid_requests.py
- [ ] T014 [P] Edge case test: invalid audio handling in tests/unit/test_invalid_audio.py
- [ ] T015 [P] Edge case test: concurrent access patterns in tests/unit/test_concurrent_access.py

## Phase 3.3: Core Implementation (ONLY after tests are failing)

### Model State Management Implementation
- [x] T016 Implement preserve-then-replace pattern in src/voiceflow/core/asr_buffer_safe.py (_reload_model_fresh method)
- [x] T017 Add safe context manager methods in src/voiceflow/core/asr_buffer_safe.py (get_safe_context, _create_null_context)
- [x] T018 Implement atomic model swapping logic in src/voiceflow/core/asr_buffer_safe.py (_atomic_model_swap method)
- [ ] T019 Add model health monitoring in src/voiceflow/core/asr_buffer_safe.py (is_model_healthy, get_model_stats methods)

### Error Recovery Implementation
- [ ] T020 [P] Implement NullObjectModel class in src/voiceflow/core/null_model.py
- [ ] T021 [P] Implement ErrorRecoveryManager class in src/voiceflow/core/error_recovery.py
- [ ] T022 Integrate error recovery into transcription flow in src/voiceflow/core/asr_buffer_safe.py (transcribe method)
- [ ] T023 Add comprehensive error logging and metrics in src/voiceflow/core/asr_buffer_safe.py

### Thread Safety Enhancements
- [ ] T024 Add compound operation locking in src/voiceflow/core/asr_buffer_safe.py (transcribe, _reload_model_fresh)
- [ ] T025 Implement thread-safe model access patterns in src/voiceflow/core/asr_buffer_safe.py
- [ ] T026 Add deadlock prevention mechanisms in src/voiceflow/core/asr_buffer_safe.py

## Phase 3.4: Integration & System Enhancement

### Configuration Updates
- [ ] T027 Update config.py with enhanced model management settings
- [ ] T028 Add model health monitoring configuration options
- [ ] T029 [P] Update installation scripts with new dependency requirements

### System Integration
- [ ] T030 Integrate new model safety into enhanced_tray.py
- [ ] T031 Update Control Center GUI with model health indicators
- [ ] T032 Add model state monitoring to visual indicators system

### Logging and Monitoring
- [ ] T033 [P] Implement detailed model state logging in src/voiceflow/utils/model_logger.py
- [ ] T034 [P] Add performance metrics collection in src/voiceflow/utils/performance_tracker.py
- [ ] T035 Update existing loggers to include model safety events

## Phase 3.5: Polish & Validation

### Enhanced Testing
- [ ] T036 [P] Unit tests for NullObjectModel in tests/unit/test_null_model.py
- [ ] T037 [P] Unit tests for ErrorRecoveryManager in tests/unit/test_error_recovery.py
- [ ] T038 [P] Unit tests for atomic model swapping in tests/unit/test_atomic_swap.py
- [ ] T039 [P] Performance regression tests in tests/performance/test_response_time.py

### Real-World Validation
- [ ] T040 Update comprehensive_test_suite.py with new test scenarios
- [ ] T041 Update real_world_test.py with extended session tests
- [ ] T042 Run 24-hour stability test with monitoring
- [ ] T043 Validate constitutional compliance (response time, memory usage)

### Documentation and Cleanup
- [ ] T044 [P] Update quickstart.md with verification steps
- [ ] T045 [P] Update CLAUDE.md with new model safety patterns
- [ ] T046 [P] Create troubleshooting guide for model issues
- [ ] T047 Remove deprecated or redundant code patterns
- [ ] T048 Final integration test with VoiceFlow Control Center

## Dependencies
- Setup (T001-T004) before all other phases
- Tests (T005-T015) MUST be written and failing before implementation (T016-T026)
- Core implementation (T016-T026) before integration (T027-T035)
- Integration complete before polish (T036-T048)
- T016 blocks T017, T018, T019 (same file modifications)
- T020, T021 can run in parallel (different files)
- T022 depends on T020, T021 completion
- T027-T029 can run in parallel (different files)
- T036-T039 can run in parallel (different files)

## Parallel Execution Examples

### Phase 3.2 - Initial Contract Tests (T005-T008)
```bash
# Launch contract tests in parallel:
python -m pytest tests/unit/test_safe_model_contract.py &
python -m pytest tests/unit/test_transcription_contract.py &
python -m pytest tests/unit/test_reload_contract.py &
python -m pytest tests/unit/test_recovery_contract.py &
wait
```

### Phase 3.2 - Integration Tests (T009-T012)
```bash
# Launch integration tests in parallel:
python -m pytest tests/integration/test_consecutive_transcriptions.py &
python -m pytest tests/integration/test_reload_failures.py &
python -m pytest tests/integration/test_nonetype_reproduction.py &
python -m pytest tests/integration/test_extended_stability.py &
wait
```

### Phase 3.3 - Independent Implementations (T020-T021)
```bash
# Implement support classes in parallel:
# Terminal 1:
vim src/voiceflow/core/null_model.py
# Terminal 2:
vim src/voiceflow/core/error_recovery.py
```

### Phase 3.5 - Final Unit Tests (T036-T039)
```bash
# Launch final validation tests:
python -m pytest tests/unit/test_null_model.py &
python -m pytest tests/unit/test_error_recovery.py &
python -m pytest tests/unit/test_atomic_swap.py &
python -m pytest tests/performance/test_response_time.py &
wait
```

## Critical Success Criteria

### Must Pass Before Completion:
1. All contract tests pass (T005-T008)
2. NoneType error reproduction test fails (proves fix works) (T011)
3. 10+ consecutive transcriptions succeed (T009)
4. Extended session stability confirmed (T012)
5. Performance within constitutional limits (T043)
6. Control Center remains functional (T048)

### Key Verification Points:
- **T003**: Document current failure rate for comparison
- **T011**: Ensure we can reproduce the original error, then verify fix
- **T016**: This is the critical fix - preserve-then-replace pattern
- **T022**: Integration point where all components work together
- **T042**: 24-hour test confirms production readiness
- **T048**: End-to-end validation with actual VoiceFlow GUI

## Notes
- Tests must fail initially (TDD approach)
- Critical fix is in T016 - preserve-then-replace pattern
- Focus on constitutional compliance throughout
- Extensive validation ensures production stability
- Parallel execution maximizes development efficiency

## Validation Checklist
*GATE: Checked before task execution*

- [x] All contracts have corresponding tests (T005-T008)
- [x] All entities have implementation tasks (ModelState, TranscriptionSession, ErrorRecoveryContext)
- [x] All tests come before implementation (Phase 3.2 before 3.3)
- [x] Parallel tasks truly independent (different files or no shared state)
- [x] Each task specifies exact file path
- [x] No task modifies same file as another [P] task
- [x] Critical fix identified and prioritized (T016)
- [x] Constitutional compliance validated (T043)
- [x] End-to-end validation included (T048)