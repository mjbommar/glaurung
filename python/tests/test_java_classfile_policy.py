from glaurung.java_classfile_policy import classfile_policy


def test_classfile_policy_labels_standard_version() -> None:
    summary = classfile_policy(61, 0, size_bytes=512)

    assert summary.java_release == 17
    assert summary.java_release_label == "Java 17"
    assert summary.classfile_version_label == "Java 17 (classfile 61.0)"
    assert summary.is_preview_classfile is False
    assert summary.classfile_size == 512
    assert summary.classfile_size_category == "normal"
    assert summary.classfile_warnings == []


def test_classfile_policy_warns_for_preview_future_and_size() -> None:
    summary = classfile_policy(71, 65535, size_bytes=11 * 1024 * 1024)

    assert summary.java_release == 27
    assert summary.java_release_label == "Java 27"
    assert summary.is_preview_classfile is True
    assert summary.classfile_size_category == "very_large"
    assert any("preview" in warning for warning in summary.classfile_warnings)
    assert any(
        "newer than Java SE 26" in warning for warning in summary.classfile_warnings
    )
    assert any("very large" in warning for warning in summary.classfile_warnings)
