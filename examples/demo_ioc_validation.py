#!/usr/bin/env python3
"""Demo script showing IOC validation with LLM filtering."""

import sys
import os
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import glaurung as g
from glaurung.llm.agents.ioc_validator import (
    IOCCandidate,
    IOCType,
    validate_iocs,
)
from glaurung.llm.config import get_config


def demo_ioc_validation():
    """Demonstrate IOC validation with false positive filtering."""
    
    print("=" * 60)
    print("IOC Validation Demo - False Positive Filtering")
    print("=" * 60)
    
    # Check if LLM is available
    config = get_config()
    if not any(config.available_models().values()):
        print("\n⚠️  No LLM API keys found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY")
        print("   Running with mock data instead...\n")
        use_mock = True
    else:
        use_mock = False
        print(f"\n✓ Using model: {config.default_model}")
    
    # Create test candidates with mix of real and false positives
    candidates = [
        IOCCandidate(
            value="192.168.1.1",
            ioc_type=IOCType.IPV4,
            context="Found in configuration section",
            encoding="ascii"
        ),
        IOCCandidate(
            value="evil-malware.tk",
            ioc_type=IOCType.DOMAIN,
            context="Hardcoded in .data section",
            encoding="ascii"
        ),
        IOCCandidate(
            value="1.2.3.4",
            ioc_type=IOCType.IPV4,
            context="Sequential pattern in binary",
            encoding="ascii"
        ),
        IOCCandidate(
            value="system.io",
            ioc_type=IOCType.DOMAIN,
            context="Package namespace in imports",
            encoding="utf16le"
        ),
        IOCCandidate(
            value="185.228.168.168",
            ioc_type=IOCType.IPV4,
            context="Encoded in obfuscated string",
            encoding="ascii"
        ),
        IOCCandidate(
            value="Main.class",
            ioc_type=IOCType.HOSTNAME,
            context="Java class file reference",
            encoding="ascii"
        ),
        IOCCandidate(
            value="https://c2-server.evil/beacon",
            ioc_type=IOCType.URL,
            context="Found in encrypted section",
            encoding="ascii"
        ),
    ]
    
    print(f"\nAnalyzing {len(candidates)} IOC candidates:")
    print("-" * 40)
    for i, c in enumerate(candidates, 1):
        print(f"{i}. [{c.ioc_type.value:8}] {c.value}")
        print(f"   Context: {c.context}")
    
    if use_mock:
        # Create mock results for demo
        from glaurung.llm.agents.ioc_validator import ValidatedIOC, IOCValidationResult
        
        mock_result = IOCValidationResult(
            validated_iocs=[
                ValidatedIOC(
                    value="192.168.1.1",
                    ioc_type=IOCType.IPV4,
                    is_valid=False,
                    confidence=1.0,
                    reasoning="Private IP address range, not external IOC"
                ),
                ValidatedIOC(
                    value="evil-malware.tk",
                    ioc_type=IOCType.DOMAIN,
                    is_valid=True,
                    confidence=0.95,
                    reasoning="Suspicious domain with commonly abused TLD (.tk)",
                    risk_level="high",
                    category="malware-c2"
                ),
                ValidatedIOC(
                    value="1.2.3.4",
                    ioc_type=IOCType.IPV4,
                    is_valid=False,
                    confidence=0.98,
                    reasoning="Sequential pattern indicates version or test data"
                ),
                ValidatedIOC(
                    value="system.io",
                    ioc_type=IOCType.DOMAIN,
                    is_valid=False,
                    confidence=1.0,
                    reasoning=".NET namespace, not a real domain"
                ),
                ValidatedIOC(
                    value="185.228.168.168",
                    ioc_type=IOCType.IPV4,
                    is_valid=True,
                    confidence=0.85,
                    reasoning="Public IP in obfuscated context, potentially malicious",
                    risk_level="medium",
                    category="suspicious-ip"
                ),
                ValidatedIOC(
                    value="Main.class",
                    ioc_type=IOCType.HOSTNAME,
                    is_valid=False,
                    confidence=1.0,
                    reasoning="Java class file name, not a hostname"
                ),
                ValidatedIOC(
                    value="https://c2-server.evil/beacon",
                    ioc_type=IOCType.URL,
                    is_valid=True,
                    confidence=0.99,
                    reasoning="C2 beacon URL pattern in encrypted section",
                    risk_level="critical",
                    category="malware-c2"
                ),
            ],
            summary="Validated 7 IOCs: 3 true positives (1 critical, 1 high, 1 medium risk), 4 false positives filtered",
            true_positive_count=3,
            false_positive_count=4,
            high_risk_iocs=["evil-malware.tk", "https://c2-server.evil/beacon"]
        )
        result = mock_result
    else:
        # Use real LLM validation
        print("\n🔍 Validating with LLM...")
        result = validate_iocs(
            candidates=candidates,
            binary_format="PE",
            binary_type="Unknown"
        )
    
    # Display results
    print("\n" + "=" * 60)
    print("VALIDATION RESULTS")
    print("=" * 60)
    print(f"\n📊 Summary: {result.summary}")
    print(f"   ✓ True Positives:  {result.true_positive_count}")
    print(f"   ✗ False Positives: {result.false_positive_count}")
    
    # Show detailed results
    print("\n" + "-" * 60)
    print("DETAILED ANALYSIS:")
    print("-" * 60)
    
    true_positives = []
    false_positives = []
    
    for ioc in result.validated_iocs:
        if ioc.is_valid:
            true_positives.append(ioc)
        else:
            false_positives.append(ioc)
    
    if true_positives:
        print("\n✅ TRUE POSITIVE IOCs (Real Threats):")
        for ioc in true_positives:
            risk_emoji = {
                "critical": "🔴",
                "high": "🟠", 
                "medium": "🟡",
                "low": "🟢"
            }.get(ioc.risk_level, "⚪")
            
            print(f"\n   {risk_emoji} {ioc.value} [{ioc.ioc_type.value}]")
            print(f"      Confidence: {ioc.confidence:.0%}")
            print(f"      Risk Level: {ioc.risk_level or 'unknown'}")
            if ioc.category:
                print(f"      Category: {ioc.category}")
            print(f"      Reasoning: {ioc.reasoning}")
    
    if false_positives:
        print("\n❌ FALSE POSITIVES (Filtered Out):")
        for ioc in false_positives:
            print(f"\n   • {ioc.value} [{ioc.ioc_type.value}]")
            print(f"     Confidence: {ioc.confidence:.0%}")
            print(f"     Reasoning: {ioc.reasoning}")
    
    if result.high_risk_iocs:
        print("\n" + "=" * 60)
        print("⚠️  HIGH RISK IOCs REQUIRING IMMEDIATE ATTENTION:")
        for ioc_val in result.high_risk_iocs:
            print(f"   🚨 {ioc_val}")
    
    print("\n" + "=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    
    reduction = (result.false_positive_count / len(candidates)) * 100 if candidates else 0
    print(f"\n📈 False Positive Reduction: {reduction:.1f}%")
    print(f"   Original IOCs: {len(candidates)}")
    print(f"   After Filtering: {result.true_positive_count}")
    print(f"   Noise Removed: {result.false_positive_count}")
    
    print("\n✨ The LLM-based validator successfully identified and filtered")
    print("   false positives while preserving true security indicators!")


if __name__ == "__main__":
    demo_ioc_validation()