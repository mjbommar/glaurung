from __future__ import annotations


_LAZY_EXPORTS = {
    "WindowsAnalystNotebookReviewConfig": ".windows_analyst_notebook_review",
    "WindowsAnalystNotebookReviewResult": ".windows_analyst_notebook_review",
    "run_windows_analyst_notebook_review": ".windows_analyst_notebook_review",
    "WindowsAnalystLoopCommand": ".windows_analyst_command_loop",
    "WindowsAnalystLoopConfig": ".windows_analyst_command_loop",
    "WindowsAnalystLoopResult": ".windows_analyst_command_loop",
    "run_windows_analyst_command_loop": ".windows_analyst_command_loop",
    "WindowsCorpusCuratorConfig": ".windows_corpus_curator",
    "WindowsCorpusCuratorResult": ".windows_corpus_curator",
    "WindowsCorpusAcceptedDrift": ".windows_corpus_curator",
    "WindowsCorpusAcceptedDriftMatch": ".windows_corpus_curator",
    "run_windows_corpus_curator": ".windows_corpus_curator",
    "WindowsEvidenceReviewConfig": ".windows_evidence_review",
    "WindowsEvidenceReviewResult": ".windows_evidence_review",
    "run_windows_evidence_review": ".windows_evidence_review",
    "WindowsFunctionizationReviewConfig": ".windows_functionization_review",
    "WindowsFunctionizationReviewResult": ".windows_functionization_review",
    "run_windows_functionization_review": ".windows_functionization_review",
    "WindowsInteractiveAnalystConfig": ".windows_interactive_analyst",
    "WindowsInteractiveAnalystResult": ".windows_interactive_analyst",
    "run_windows_interactive_analyst": ".windows_interactive_analyst",
    "WindowsPatchFunctionIdentity": ".windows_patch_diff_review",
    "WindowsPatchDiffReviewConfig": ".windows_patch_diff_review",
    "WindowsPatchDiffReviewResult": ".windows_patch_diff_review",
    "run_windows_patch_diff_review": ".windows_patch_diff_review",
    "WindowsRuleAuthoringConfig": ".windows_rule_authoring",
    "WindowsRuleAuthoringResult": ".windows_rule_authoring",
    "run_windows_rule_authoring": ".windows_rule_authoring",
    "WindowsSinkToGateReviewConfig": ".windows_sink_to_gate_review",
    "WindowsSinkToGateReviewResult": ".windows_sink_to_gate_review",
    "WindowsSinkToGateReviewBatchConfig": ".windows_sink_to_gate_review",
    "WindowsSinkToGateReviewBatchResult": ".windows_sink_to_gate_review",
    "run_windows_sink_to_gate_review": ".windows_sink_to_gate_review",
    "run_windows_sink_to_gate_review_batch": ".windows_sink_to_gate_review",
    "WindowsChangedFunctionFact": ".windows_triage_worklist",
    "WindowsTriageTargetFanoutBatch": ".windows_triage_worklist",
    "WindowsTriageWorklistConfig": ".windows_triage_worklist",
    "WindowsTriageWorklistResult": ".windows_triage_worklist",
    "run_windows_triage_worklist": ".windows_triage_worklist",
    "WindowsTargetPipelineConfig": ".windows_target_pipeline",
    "WindowsTargetPipelineResult": ".windows_target_pipeline",
    "WindowsTargetPipelineBlockerWorkItem": ".windows_target_pipeline",
    "WindowsTargetPipelineBlockerWorklist": ".windows_target_pipeline",
    "run_windows_target_pipeline": ".windows_target_pipeline",
    "WindowsValidationPlanningConfig": ".windows_validation_planning",
    "WindowsValidationPlanningResult": ".windows_validation_planning",
    "WindowsValidationBuildCorpusPacketScanConfig": ".windows_validation_planning",
    "WindowsValidationPlanningBatchConfig": ".windows_validation_planning",
    "WindowsValidationPlanningBatchResult": ".windows_validation_planning",
    "run_windows_validation_planning": ".windows_validation_planning",
    "run_windows_validation_planning_batch": ".windows_validation_planning",
}


def __getattr__(name: str):
    if module_name := _LAZY_EXPORTS.get(name):
        from importlib import import_module

        module = import_module(module_name, __name__)
        return getattr(module, name)
    if name in {
        "build_java_recovery_agent",
        "build_java_security_agent",
        "build_java_triage_agent",
    }:
        from . import java

        return getattr(java, name)
    if name in {
        "run_java_agent_analysis",
        "run_java_recovery_analysis",
        "run_java_security_analysis",
        "run_java_triage_analysis",
    }:
        from . import java_runner

        return getattr(java_runner, name)
    if name == "create_memory_agent":
        from .memory_agent import create_memory_agent

        return create_memory_agent
    raise AttributeError(name)


__all__ = [
    "build_java_recovery_agent",
    "build_java_security_agent",
    "build_java_triage_agent",
    "create_memory_agent",
    "run_java_agent_analysis",
    "run_java_recovery_analysis",
    "run_java_security_analysis",
    "run_java_triage_analysis",
    "WindowsAnalystNotebookReviewConfig",
    "WindowsAnalystNotebookReviewResult",
    "WindowsAnalystLoopCommand",
    "WindowsAnalystLoopConfig",
    "WindowsAnalystLoopResult",
    "WindowsChangedFunctionFact",
    "WindowsCorpusCuratorConfig",
    "WindowsCorpusCuratorResult",
    "WindowsCorpusAcceptedDrift",
    "WindowsCorpusAcceptedDriftMatch",
    "WindowsEvidenceReviewConfig",
    "WindowsEvidenceReviewResult",
    "WindowsFunctionizationReviewConfig",
    "WindowsFunctionizationReviewResult",
    "WindowsInteractiveAnalystConfig",
    "WindowsInteractiveAnalystResult",
    "WindowsPatchFunctionIdentity",
    "WindowsPatchDiffReviewConfig",
    "WindowsPatchDiffReviewResult",
    "WindowsRuleAuthoringConfig",
    "WindowsRuleAuthoringResult",
    "WindowsSinkToGateReviewConfig",
    "WindowsSinkToGateReviewResult",
    "WindowsSinkToGateReviewBatchConfig",
    "WindowsSinkToGateReviewBatchResult",
    "WindowsTriageWorklistConfig",
    "WindowsTriageTargetFanoutBatch",
    "WindowsTriageWorklistResult",
    "WindowsTargetPipelineConfig",
    "WindowsTargetPipelineResult",
    "WindowsTargetPipelineBlockerWorkItem",
    "WindowsTargetPipelineBlockerWorklist",
    "WindowsValidationPlanningConfig",
    "WindowsValidationBuildCorpusPacketScanConfig",
    "WindowsValidationPlanningBatchConfig",
    "WindowsValidationPlanningBatchResult",
    "WindowsValidationPlanningResult",
    "run_windows_analyst_notebook_review",
    "run_windows_analyst_command_loop",
    "run_windows_corpus_curator",
    "run_windows_evidence_review",
    "run_windows_functionization_review",
    "run_windows_interactive_analyst",
    "run_windows_patch_diff_review",
    "run_windows_rule_authoring",
    "run_windows_sink_to_gate_review",
    "run_windows_sink_to_gate_review_batch",
    "run_windows_target_pipeline",
    "run_windows_triage_worklist",
    "run_windows_validation_planning",
    "run_windows_validation_planning_batch",
]
