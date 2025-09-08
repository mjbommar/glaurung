#!/usr/bin/env python3
"""Analyze a binary and validate its IOCs with LLM filtering."""

import sys
import argparse
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import glaurung as g
from glaurung.llm.agents.ioc_validator_v2 import (
    filter_iocs_from_artifact_v2,
)
from glaurung.llm.config import get_config


def analyze_and_validate(file_path: str):
    """Analyze a binary and validate detected IOCs."""
    
    print(f"\n📂 Analyzing: {file_path}")
    print("=" * 60)
    
    # Perform triage analysis
    try:
        # Try with all parameters
        artifact = g.triage.analyze_path(
            file_path,
            10_485_760,  # max_read_bytes
            104_857_600,  # max_file_size
            1,  # max_depth
            4,  # str_min_len
            100,  # str_max_samples
            False,  # str_lang
            0,  # str_max_lang_detect
            True,  # str_classify
            200,  # str_max_classify
            16,  # str_max_ioc_per_string
        )
    except (TypeError, Exception):
        # Fallback - simple call
        artifact = g.triage.analyze_path(file_path)
    
    # Display basic info
    print(f"Size: {artifact.size_bytes:,} bytes")
    if artifact.verdicts:
        v = artifact.verdicts[0]
        print(f"Format: {v.format} ({v.arch}, {v.bits}-bit)")
    
    # Check for IOCs
    if not artifact.strings or not artifact.strings.ioc_counts:
        print("\n✓ No IOCs detected in this binary")
        return
    
    # Display raw IOC counts
    print("\n📊 Raw IOC Detection (before validation):")
    print("-" * 40)
    total_iocs = 0
    for ioc_type, count in sorted(artifact.strings.ioc_counts.items()):
        if count > 0:
            print(f"  {ioc_type:15} : {count}")
            total_iocs += count
    
    if total_iocs == 0:
        print("\n✓ No IOCs detected")
        return
    
    print(f"\nTotal IOCs detected: {total_iocs}")
    
    # Check if LLM is available
    config = get_config()
    if not any(config.available_models().values()):
        print("\n⚠️  No LLM API key found. Cannot validate IOCs.")
        print("   Set OPENAI_API_KEY or ANTHROPIC_API_KEY to enable validation.")
        
        # Show sample IOCs without validation
        if artifact.strings.ioc_samples:
            print("\n📝 Sample IOCs (unvalidated):")
            for sample in artifact.strings.ioc_samples[:10]:
                print(f"  [{sample.kind:12}] {sample.text}")
        return
    
    # Validate IOCs with LLM
    print(f"\n🤖 Validating IOCs with {config.default_model}...")
    print("-" * 40)
    
    try:
        validated_iocs = filter_iocs_from_artifact_v2(artifact)
        
        if not validated_iocs:
            print("✅ All detected IOCs are false positives!")
            print("   No real security indicators found.")
            
            # Show what was filtered
            if artifact.strings.ioc_samples:
                print("\n📝 Examples of filtered false positives:")
                for sample in artifact.strings.ioc_samples[:5]:
                    print(f"  ✗ [{sample.kind:8}] {sample.text}")
        else:
            print(f"\n⚠️  {len(validated_iocs)} CONFIRMED IOCs:")
            print("-" * 40)
            
            # Group by risk level
            critical = [ioc for ioc in validated_iocs if ioc.risk_level == "critical"]
            high = [ioc for ioc in validated_iocs if ioc.risk_level == "high"]
            medium = [ioc for ioc in validated_iocs if ioc.risk_level == "medium"]
            low = [ioc for ioc in validated_iocs if ioc.risk_level == "low"]
            unknown = [ioc for ioc in validated_iocs if not ioc.risk_level]
            
            if critical:
                print("\n🔴 CRITICAL RISK:")
                for ioc in critical:
                    print(f"   {ioc.value} [{ioc.ioc_type.value}]")
                    print(f"     → {ioc.reasoning}")
            
            if high:
                print("\n🟠 HIGH RISK:")
                for ioc in high:
                    print(f"   {ioc.value} [{ioc.ioc_type.value}]")
                    print(f"     → {ioc.reasoning}")
            
            if medium:
                print("\n🟡 MEDIUM RISK:")
                for ioc in medium:
                    print(f"   {ioc.value} [{ioc.ioc_type.value}]")
                    print(f"     → {ioc.reasoning}")
            
            if low:
                print("\n🟢 LOW RISK:")
                for ioc in low:
                    print(f"   {ioc.value} [{ioc.ioc_type.value}]")
                    print(f"     → {ioc.reasoning}")
            
            if unknown:
                print("\n⚪ UNRATED:")
                for ioc in unknown:
                    print(f"   {ioc.value} [{ioc.ioc_type.value}]")
            
            # Summary
            raw_count = len(artifact.strings.ioc_samples) if artifact.strings.ioc_samples else 0
            print("\n" + "=" * 60)
            print("VALIDATION SUMMARY")
            print("=" * 60)
            print(f"Raw IOCs detected: {raw_count}")
            print(f"Validated as real: {len(validated_iocs)}")
            print(f"False positives removed: {raw_count - len(validated_iocs)}")
            
            if critical or high:
                print("\n🚨 ACTION REQUIRED: High-risk IOCs detected!")
                print("   This binary may be malicious.")
    
    except Exception as e:
        print(f"\n❌ Error during IOC validation: {e}")
        import traceback
        if Path(".").joinpath(".env").exists():
            traceback.print_exc()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze a binary and validate its IOCs with LLM filtering"
    )
    parser.add_argument("file", help="Path to binary file to analyze")
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Show verbose output"
    )
    
    args = parser.parse_args()
    
    if not Path(args.file).exists():
        print(f"Error: File not found: {args.file}")
        sys.exit(1)
    
    analyze_and_validate(args.file)


if __name__ == "__main__":
    main()