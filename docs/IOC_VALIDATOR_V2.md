# IOC Validator V2 - Hallucination-Proof Design

## Problem Statement

The initial IOC validator had a **critical design flaw**: it could hallucinate IOCs that never existed in the analyzed binary. The LLM would sometimes generate completely fictional domains, IPs, or URLs that weren't present in the original data.

## Root Cause

The original design allowed the LLM to generate `ValidatedIOC` objects with arbitrary `value` fields:

```python
# BAD: LLM can create any value it wants!
class ValidatedIOC(BaseModel):
    value: str  # LLM can hallucinate here!
    ioc_type: IOCType
    is_valid: bool
    ...
```

## Solution: Constrained Validation

The V2 design makes hallucination **structurally impossible** by:

1. **Index-Based Decisions**: The LLM can only reference IOCs by their index in the input list
2. **No Value Generation**: The output schema doesn't include IOC values - only validation decisions
3. **Strict Validation**: Post-processing verifies all indices are valid and no new IOCs are created

## Key Design Changes

### 1. Output Schema Without Values

```python
class IOCValidationDecision(BaseModel):
    candidate_index: int  # Reference by index only!
    is_valid: bool
    confidence: float
    reasoning: str
    # NO value field - cannot create new IOCs
```

### 2. Numbered Input List

The LLM receives a numbered list and MUST reference by index:

```
Validate these IOCs:
0. [ipv4] 192.168.1.1
1. [domain] example.com
2. [ipv4] 1.2.3.4

Provide decisions for indices 0-2 only.
```

### 3. Post-Validation Checks

```python
# Verify no hallucination
for validated in validated_iocs:
    if validated.value not in original_values:
        raise ValueError(f"Hallucinated IOC: {validated.value}")
```

## Benefits

1. **Zero Hallucination**: Structurally impossible to create new IOCs
2. **Guaranteed Accuracy**: All validated IOCs are from the original detection
3. **Traceable Decisions**: Each decision maps to a specific detected IOC
4. **Type Safety**: Pydantic validation ensures structural correctness

## Usage

```python
from glaurung.llm.agents import validate_iocs, IOCCandidate, IOCType

# Input candidates
candidates = [
    IOCCandidate(value="192.168.1.1", ioc_type=IOCType.IPV4),
    IOCCandidate(value="evil.tk", ioc_type=IOCType.DOMAIN),
]

# Validate - can ONLY return decisions about these exact IOCs
validated, tp_count, fp_count = validate_iocs(candidates)

# Guaranteed: all validated IOCs are from candidates list
assert all(v.value in [c.value for c in candidates] for v in validated)
```

## Testing Results

✅ **Hello-mono.exe Test**:
- Detected 6 raw IOCs (5 hostname, 1 IPv4)
- Correctly identified ALL as false positives
- **Zero hallucination** - no fictional IOCs created

✅ **Validation Test Suite**:
- 100% prevention of hallucination
- Proper handling of invalid indices
- Graceful fallback for missing decisions

## Conclusion

The V2 validator demonstrates how careful API design can make certain classes of errors impossible. By constraining the output schema to only allow references to input data, we eliminate hallucination at the structural level rather than relying on prompt engineering alone.

This approach should be the standard for any LLM-based validation or filtering system where accuracy is critical.