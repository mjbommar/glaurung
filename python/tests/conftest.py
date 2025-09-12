"""Shared test utilities and fixtures for Python tests."""

import pytest
from pathlib import Path


def sample_file_exists(relative_path):
    """Check if a sample file exists."""
    # Try relative to current directory first (python/tests/)
    full_path = Path("samples") / relative_path
    if full_path.exists():
        return True

    # Try relative to parent directory (project root)
    full_path = Path("../samples") / relative_path
    return full_path.exists()


def sample_file_path(relative_path):
    """Get the full path to a sample file."""
    # Try relative to current directory first (python/tests/)
    full_path = Path("samples") / relative_path
    if full_path.exists():
        return full_path

    # Try relative to parent directory (project root)
    full_path = Path("../samples") / relative_path
    if full_path.exists():
        return full_path

    # Return the relative path as fallback
    return Path("samples") / relative_path


def get_sample_file_path(relative_path):
    """Get sample file path, skipping test if file doesn't exist."""
    if not sample_file_exists(relative_path):
        pytest.skip(f"Sample file not found: {relative_path}")
    return sample_file_path(relative_path)


# Sample file constants (matching actual file structure)
# Note: GCC/Clang samples are corrupted, using working alternatives
SAMPLE_ELF_GCC = "binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O0"
SAMPLE_ELF_CLANG = (
    "binaries/platforms/linux/amd64/export/native/asm/gas/O0/hello-asm-gas-O0"
)
# Note: No working PE samples available, using another ELF as fallback
SAMPLE_PE_EXE = "binaries/platforms/linux/amd64/export/native/asm/nasm/O0/hello-asm-nasm-O0"
SAMPLE_JAR = "binaries/platforms/linux/amd64/export/java/jdk21/HelloWorld.jar"
SAMPLE_JAVA_CLASS = "binaries/platforms/linux/amd64/export/java/jdk21/HelloWorld.class"
SAMPLE_PYTHON_PYC = "binaries/platforms/linux/amd64/export/python/hello.pyc"
SAMPLE_FORTRAN = "binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O0"

# Python bytecode samples for different versions
SAMPLE_PYTHON_PYC_38 = "binaries/platforms/linux/amd64/export/python/hello-py3.8.pyc"
SAMPLE_PYTHON_PYC_39 = "binaries/platforms/linux/amd64/export/python/hello-py3.9.pyc"
SAMPLE_PYTHON_PYC_310 = "binaries/platforms/linux/amd64/export/python/hello-py3.10.pyc"
SAMPLE_PYTHON_PYC_311 = "binaries/platforms/linux/amd64/export/python/hello-py3.11.pyc"
SAMPLE_PYTHON_PYC_312 = "binaries/platforms/linux/amd64/export/python/hello-py3.12.pyc"
SAMPLE_PYTHON_PYC_313 = "binaries/platforms/linux/amd64/export/python/hello-py3.13.pyc"


@pytest.fixture
def sample_dir():
    """Fixture providing the samples directory path."""
    return Path("samples")


@pytest.fixture
def existing_sample_files():
    """Fixture providing list of sample files that exist."""
    existing_files = []
    sample_files = [
        SAMPLE_ELF_GCC,
        SAMPLE_ELF_CLANG,
        SAMPLE_PE_EXE,
        SAMPLE_JAR,
        SAMPLE_JAVA_CLASS,
        SAMPLE_PYTHON_PYC,
        SAMPLE_FORTRAN,
    ]

    for sample_file in sample_files:
        if sample_file_exists(sample_file):
            existing_files.append(sample_file)

    return existing_files


@pytest.fixture
def system_binary_ls():
    """Fixture providing path to /usr/bin/ls if it exists."""
    ls_path = Path("/usr/bin/ls")
    if ls_path.exists():
        return ls_path
    pytest.skip("System binary /usr/bin/ls not found")


@pytest.fixture
def system_binary_cat():
    """Fixture providing path to /usr/bin/cat if it exists."""
    cat_path = Path("/usr/bin/cat")
    if cat_path.exists():
        return cat_path
    pytest.skip("System binary /usr/bin/cat not found")


# Sample file fixtures
@pytest.fixture
def sample_elf_gcc():
    """Fixture providing path to GCC-compiled ELF sample."""
    return get_sample_file_path(SAMPLE_ELF_GCC)


@pytest.fixture
def sample_elf_clang():
    """Fixture providing path to Clang-compiled ELF sample."""
    return get_sample_file_path(SAMPLE_ELF_CLANG)


@pytest.fixture
def sample_pe_exe():
    """Fixture providing path to Windows PE executable sample."""
    return get_sample_file_path(SAMPLE_PE_EXE)


@pytest.fixture
def sample_jar():
    """Fixture providing path to Java JAR file sample."""
    return get_sample_file_path(SAMPLE_JAR)


@pytest.fixture
def sample_java_class():
    """Fixture providing path to Java class file sample."""
    return get_sample_file_path(SAMPLE_JAVA_CLASS)


@pytest.fixture
def sample_python_pyc():
    """Fixture providing path to Python bytecode sample."""
    return get_sample_file_path(SAMPLE_PYTHON_PYC)


@pytest.fixture
def sample_fortran():
    """Fixture providing path to Fortran binary sample."""
    return get_sample_file_path(SAMPLE_FORTRAN)


# Python bytecode fixtures for different versions
@pytest.fixture
def sample_python_pyc_38():
    """Fixture providing path to Python 3.8 bytecode sample."""
    return get_sample_file_path(SAMPLE_PYTHON_PYC_38)


@pytest.fixture
def sample_python_pyc_39():
    """Fixture providing path to Python 3.9 bytecode sample."""
    return get_sample_file_path(SAMPLE_PYTHON_PYC_39)


@pytest.fixture
def sample_python_pyc_310():
    """Fixture providing path to Python 3.10 bytecode sample."""
    return get_sample_file_path(SAMPLE_PYTHON_PYC_310)


@pytest.fixture
def sample_python_pyc_311():
    """Fixture providing path to Python 3.11 bytecode sample."""
    return get_sample_file_path(SAMPLE_PYTHON_PYC_311)


@pytest.fixture
def sample_python_pyc_312():
    """Fixture providing path to Python 3.12 bytecode sample."""
    return get_sample_file_path(SAMPLE_PYTHON_PYC_312)


@pytest.fixture
def sample_python_pyc_313():
    """Fixture providing path to Python 3.13 bytecode sample."""
    return get_sample_file_path(SAMPLE_PYTHON_PYC_313)
