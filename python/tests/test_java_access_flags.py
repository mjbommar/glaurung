from glaurung.llm.tools.java_access_flags import access_flag_names


def test_access_flag_names_decode_context_specific_bits() -> None:
    assert access_flag_names(0x0021, "class") == ["public", "super"]
    assert access_flag_names(0x001A, "field") == ["private", "static", "final"]
    assert access_flag_names(0x0141, "method") == ["public", "bridge", "native"]
    assert access_flag_names(0x0609, "inner_class") == [
        "public",
        "static",
        "interface",
        "abstract",
    ]
    assert access_flag_names(0x8010, "parameter") == ["final", "mandated"]
