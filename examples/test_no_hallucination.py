#!/usr/bin/env python3
"""Test that the V2 validator doesn't hallucinate IOCs."""

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from glaurung.llm.agents.ioc_validator_v2 import (
    IOCCandidate,
    IOCType,
    validate_iocs_v2,
)
from glaurung.llm.config import get_config


def test_no_hallucination():
    """Verify the validator cannot create new IOCs."""
    
    print("=" * 60)
    print("Testing Hallucination Prevention in IOC Validator V2")
    print("=" * 60)
    
    # Check if LLM is available
    config = get_config()
    if not any(config.available_models().values()):
        print("\n⚠️  No LLM API keys found. Using mock test instead.")
        use_real_llm = False
    else:
        print(f"\n✓ Using model: {config.default_model}")
        use_real_llm = True
    
    # Create specific test candidates
    test_candidates = [
        IOCCandidate(
            value="192.168.1.1",  
            ioc_type=IOCType.IPV4,
            context="Private IP in config"
        ),
        IOCCandidate(
            value="1.2.3.4",
            ioc_type=IOCType.IPV4,
            context="Version number pattern"
        ),
        IOCCandidate(
            value="evil.example.com",
            ioc_type=IOCType.DOMAIN,
            context="Suspicious domain"
        ),
    ]
    
    print(f"\n📝 Input IOCs ({len(test_candidates)}):")
    for i, c in enumerate(test_candidates):
        print(f"  {i}. [{c.ioc_type.value:8}] {c.value}")
    
    original_values = [c.value for c in test_candidates]
    print(f"\nOriginal values: {original_values}")
    
    if use_real_llm:
        # Test with real LLM
        print("\n🔍 Validating with LLM...")
        validated, tp, fp = validate_iocs_v2(test_candidates)
    else:
        # Mock test
        from unittest.mock import MagicMock, patch
        from glaurung.llm.agents.ioc_validator_v2 import (
            IOCValidationDecision,
            IOCValidationOutput,
        )
        
        mock_response = IOCValidationOutput(
            decisions=[
                IOCValidationDecision(
                    candidate_index=0,
                    is_valid=False,
                    confidence=1.0,
                    reasoning="Private IP"
                ),
                IOCValidationDecision(
                    candidate_index=1,
                    is_valid=False,
                    confidence=0.95,
                    reasoning="Version pattern"
                ),
                IOCValidationDecision(
                    candidate_index=2,
                    is_valid=True,
                    confidence=0.8,
                    reasoning="Suspicious subdomain"
                ),
            ],
            summary="3 IOCs validated"
        )
        
        mock_agent = MagicMock()
        mock_agent.run_sync.return_value = MagicMock(output=mock_response)
        
        with patch('glaurung.llm.agents.ioc_validator_v2.create_ioc_validator_v2', return_value=mock_agent):
            validated, tp, fp = validate_iocs_v2(test_candidates)
    
    print(f"\n📊 Results:")
    print(f"  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    
    print(f"\n🔍 Checking for hallucination...")
    
    # CRITICAL CHECK: Verify no hallucination
    all_valid = True
    for v in validated:
        if v.value not in original_values:
            print(f"  ❌ HALLUCINATION DETECTED: '{v.value}' not in original list!")
            all_valid = False
        else:
            print(f"  ✓ '{v.value}' is from original list")
    
    if all_valid:
        print("\n✅ SUCCESS: No hallucination detected!")
        print("   All validated IOCs are from the original input list.")
    else:
        print("\n❌ FAILURE: Hallucination detected!")
        print("   The validator created IOCs that weren't in the input.")
        sys.exit(1)
    
    # Show validation details
    print("\n📝 Validation Details:")
    for v in validated:
        status = "✓ VALID" if v.is_valid else "✗ FALSE POSITIVE"
        print(f"\n  {status}: {v.value}")
        print(f"    Confidence: {v.confidence:.0%}")
        print(f"    Reasoning: {v.reasoning}")
        if v.risk_level:
            print(f"    Risk: {v.risk_level}")
    
    print("\n" + "=" * 60)
    print("✨ The V2 validator successfully prevents hallucination!")
    print("   All outputs are constrained to the input candidates.")
    print("=" * 60)


if __name__ == "__main__":
    test_no_hallucination()