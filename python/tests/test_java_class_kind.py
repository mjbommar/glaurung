from glaurung.llm.tools.java_class_kind import class_kind


def test_class_kind_normalizes_jvm_shapes() -> None:
    assert (
        class_kind(
            class_name="module-info",
            access_flags=0x8000,
            super_class=None,
            record_components=[],
            module_info={"name": "demo"},
        )
        == "module"
    )
    assert (
        class_kind(
            class_name="Marker",
            access_flags=0x2600,
            super_class="java/lang/Object",
            record_components=[],
            module_info=None,
        )
        == "annotation"
    )
    assert (
        class_kind(
            class_name="Shape",
            access_flags=0x0600,
            super_class="java/lang/Object",
            record_components=[],
            module_info=None,
        )
        == "interface"
    )
    assert (
        class_kind(
            class_name="Mode",
            access_flags=0x4030,
            super_class="java/lang/Enum",
            record_components=[],
            module_info=None,
        )
        == "enum"
    )
    assert (
        class_kind(
            class_name="Pair",
            access_flags=0x0030,
            super_class="java/lang/Record",
            record_components=[{"name": "id"}],
            module_info=None,
        )
        == "record"
    )
