from __future__ import annotations

from pydantic import BaseModel, Field


class JavaClassSignatureSummary(BaseModel):
    type_parameters: list[str] = Field(default_factory=list)
    super_class: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    error: str | None = None


class JavaFieldSignatureSummary(BaseModel):
    field_type: str | None = None
    error: str | None = None


class JavaMethodSignatureSummary(BaseModel):
    type_parameters: list[str] = Field(default_factory=list)
    parameter_types: list[str] = Field(default_factory=list)
    return_type: str | None = None
    throws: list[str] = Field(default_factory=list)
    error: str | None = None


_BASE_TYPES = {
    "B": "byte",
    "C": "char",
    "D": "double",
    "F": "float",
    "I": "int",
    "J": "long",
    "S": "short",
    "Z": "boolean",
    "V": "void",
}


def decode_class_signature(signature: str | None) -> JavaClassSignatureSummary:
    if not signature:
        return JavaClassSignatureSummary()
    parser = _SignatureParser(signature)
    try:
        type_parameters = parser.parse_type_parameters()
        super_class = parser.parse_type_signature(allow_void=False)
        interfaces: list[str] = []
        while not parser.done:
            interfaces.append(parser.parse_type_signature(allow_void=False))
        return JavaClassSignatureSummary(
            type_parameters=type_parameters,
            super_class=super_class,
            interfaces=interfaces,
        )
    except ValueError as exc:
        return JavaClassSignatureSummary(error=str(exc))


def decode_field_signature(signature: str | None) -> JavaFieldSignatureSummary:
    if not signature:
        return JavaFieldSignatureSummary()
    parser = _SignatureParser(signature)
    try:
        field_type = parser.parse_type_signature(allow_void=False)
        parser.expect_done()
        return JavaFieldSignatureSummary(field_type=field_type)
    except ValueError as exc:
        return JavaFieldSignatureSummary(error=str(exc))


def decode_method_signature(signature: str | None) -> JavaMethodSignatureSummary:
    if not signature:
        return JavaMethodSignatureSummary()
    parser = _SignatureParser(signature)
    try:
        type_parameters = parser.parse_type_parameters()
        parser.expect("(")
        parameter_types: list[str] = []
        while parser.peek() != ")":
            parameter_types.append(parser.parse_type_signature(allow_void=False))
        parser.expect(")")
        return_type = parser.parse_type_signature(allow_void=True)
        throws: list[str] = []
        while not parser.done:
            parser.expect("^")
            throws.append(parser.parse_type_signature(allow_void=False))
        return JavaMethodSignatureSummary(
            type_parameters=type_parameters,
            parameter_types=parameter_types,
            return_type=return_type,
            throws=throws,
        )
    except ValueError as exc:
        return JavaMethodSignatureSummary(error=str(exc))


class _SignatureParser:
    def __init__(self, signature: str) -> None:
        self.signature = signature
        self.pos = 0

    @property
    def done(self) -> bool:
        return self.pos >= len(self.signature)

    def peek(self) -> str:
        if self.done:
            raise ValueError("unexpected end of signature")
        return self.signature[self.pos]

    def expect(self, value: str) -> None:
        if self.peek() != value:
            raise ValueError(f"expected {value!r} at offset {self.pos}")
        self.pos += 1

    def expect_done(self) -> None:
        if not self.done:
            raise ValueError(f"trailing signature data at offset {self.pos}")

    def parse_type_parameters(self) -> list[str]:
        if self.done or self.signature[self.pos] != "<":
            return []
        self.pos += 1
        out: list[str] = []
        while self.peek() != ">":
            name = self.read_until(":")
            self.expect(":")
            bounds: list[str] = []
            if self.peek() != ":":
                bounds.append(self.parse_type_signature(allow_void=False))
            while not self.done and self.peek() == ":":
                self.pos += 1
                bounds.append(self.parse_type_signature(allow_void=False))
            if bounds and bounds != ["java.lang.Object"]:
                out.append(f"{name} extends {' & '.join(bounds)}")
            else:
                out.append(name)
        self.expect(">")
        return out

    def parse_type_signature(self, *, allow_void: bool) -> str:
        dimensions = 0
        while self.peek() == "[":
            dimensions += 1
            self.pos += 1
        tag = self.peek()
        if tag == "L":
            parsed = self.parse_class_type_signature()
        elif tag == "T":
            self.pos += 1
            parsed = self.read_until(";")
            self.expect(";")
        elif tag in _BASE_TYPES:
            if tag == "V" and (dimensions or not allow_void):
                raise ValueError("void is only valid as a method return type")
            parsed = _BASE_TYPES[tag]
            self.pos += 1
        else:
            raise ValueError(f"unknown signature tag {tag!r} at offset {self.pos}")
        return parsed + "[]" * dimensions

    def parse_class_type_signature(self) -> str:
        self.expect("L")
        parsed = self.read_until_any("<.;").replace("/", ".")
        if not parsed:
            raise ValueError("empty class type")
        if not self.done and self.peek() == "<":
            parsed += self.parse_type_arguments()
        while not self.done and self.peek() == ".":
            self.pos += 1
            inner = self.read_until_any("<.;")
            if not inner:
                raise ValueError("empty inner class type")
            parsed += f".{inner}"
            if not self.done and self.peek() == "<":
                parsed += self.parse_type_arguments()
        self.expect(";")
        return parsed

    def parse_type_arguments(self) -> str:
        self.expect("<")
        args: list[str] = []
        while self.peek() != ">":
            tag = self.peek()
            if tag == "*":
                self.pos += 1
                args.append("?")
            elif tag == "+":
                self.pos += 1
                args.append(f"? extends {self.parse_type_signature(allow_void=False)}")
            elif tag == "-":
                self.pos += 1
                args.append(f"? super {self.parse_type_signature(allow_void=False)}")
            else:
                args.append(self.parse_type_signature(allow_void=False))
        self.expect(">")
        return f"<{', '.join(args)}>"

    def read_until(self, terminator: str) -> str:
        start = self.pos
        while not self.done and self.signature[self.pos] != terminator:
            self.pos += 1
        if self.done:
            raise ValueError(f"missing terminator {terminator!r}")
        return self.signature[start : self.pos]

    def read_until_any(self, terminators: str) -> str:
        start = self.pos
        while not self.done and self.signature[self.pos] not in terminators:
            self.pos += 1
        return self.signature[start : self.pos]
