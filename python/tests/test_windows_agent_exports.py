from __future__ import annotations


def test_windows_high_level_agents_are_package_visible() -> None:
    from glaurung.llm import agents

    assert agents.WindowsFunctionizationReviewConfig is not None
    assert agents.WindowsChangedFunctionFact is not None
    assert agents.WindowsTriageWorklistConfig is not None
    assert agents.WindowsTriageTargetFanoutBatch is not None
    assert agents.WindowsTargetPipelineConfig is not None
    assert agents.WindowsSinkToGateReviewConfig is not None
    assert agents.WindowsSinkToGateReviewBatchConfig is not None
    assert agents.WindowsPatchFunctionIdentity is not None
    assert agents.WindowsPatchDiffReviewConfig is not None
    assert agents.WindowsValidationPlanningConfig is not None
    assert agents.WindowsValidationBuildCorpusPacketScanConfig is not None
    assert agents.WindowsValidationPlanningBatchConfig is not None
    assert agents.WindowsAnalystNotebookReviewConfig is not None
    assert agents.WindowsRuleAuthoringConfig is not None
    assert agents.WindowsCorpusCuratorConfig is not None
    assert agents.WindowsCorpusAcceptedDrift is not None
    assert agents.WindowsCorpusAcceptedDriftMatch is not None
    assert agents.WindowsEvidenceReviewConfig is not None
    assert agents.WindowsInteractiveAnalystConfig is not None
    assert agents.WindowsAnalystLoopConfig is not None
    assert agents.WindowsAnalystLoopCommand is not None
