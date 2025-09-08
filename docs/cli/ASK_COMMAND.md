# Glaurung Ask Command - Natural Language Binary Analysis

The `glaurung ask` command provides a natural language interface for binary analysis. Ask questions in plain English and get intelligent answers powered by LLM analysis tools.

## Features

- **Natural Language Q&A**: Ask questions in plain English
- **Multiple Output Formats**: plain, rich, JSON, JSONL
- **Interactive Mode**: Chat-like interface for exploration
- **Tool Transparency**: Optionally see which tools are used
- **Batch Processing**: Ask multiple questions at once

## Basic Usage

### Single Question
```bash
glaurung ask /path/to/binary --ask "Is this malware?"
```

### Multiple Questions
```bash
glaurung ask /path/to/binary --multiple \
  "What type of binary is this?" \
  "Is it packed?" \
  "Any network IOCs?"
```

### Quick Malware Analysis
```bash
glaurung ask /path/to/binary --quick
```
This asks common malware analysis questions automatically.

### Interactive Mode
```bash
glaurung ask /path/to/binary --interactive
```
Enter a chat-like interface where you can ask questions interactively.

## Output Formats

### Rich Format (Default)
Beautiful colored output with panels and formatting:
```bash
glaurung ask /bin/ls --ask "Is this packed?"
```

### Plain Text
Simple text output without colors:
```bash
glaurung ask /bin/ls --ask "Is this packed?" --format plain
```

### JSON
Structured JSON output for scripting:
```bash
glaurung ask /bin/ls --ask "Is this packed?" --format json
```

### JSONL
One JSON object per line for streaming:
```bash
glaurung ask /bin/ls --multiple "Q1" "Q2" --format jsonl
```

## Advanced Features

### Show Tool Calls
See which analysis tools are being used:
```bash
glaurung ask /bin/ls --ask "Find IOCs" --show-tools
```

### Show Planning
See the LLM's reasoning process:
```bash
glaurung ask /bin/ls --ask "Analyze this" --show-plan
```

### Read Questions from STDIN
```bash
echo "Is this malware?" | glaurung ask /bin/ls --stdin
```

### Custom Model
Use a different LLM model:
```bash
glaurung ask /bin/ls --ask "Analyze" --model "openai:gpt-4"
```

## Examples

### Example 1: Quick Malware Check
```bash
$ glaurung ask suspicious.exe --quick --format json
```
Output:
```json
{
  "binary": "suspicious.exe",
  "questions": 5,
  "results": [
    {
      "question": "Is this binary likely malicious?",
      "answer": "Based on analysis...",
      "tool_calls": [],
      "reasoning": null
    }
  ]
}
```

### Example 2: Interactive Analysis
```bash
$ glaurung ask malware.bin --interactive

Entering interactive mode. Type 'exit' to quit.
Ready for questions!

❓ Question: What are the imported functions?
💬 Answer: The binary imports several suspicious functions...

❓ Question: Check for network IOCs
💬 Answer: Found the following network indicators...

❓ Question: exit
Interactive session ended.
```

### Example 3: Batch Analysis with Tool Visibility
```bash
$ glaurung ask sample.exe \
    --multiple "Is it packed?" "Any IOCs?" \
    --show-tools \
    --format plain
```

Output shows questions, tool calls, and answers in plain text.

### Example 4: Scripting with JSONL
```bash
#!/bin/bash
# Analyze multiple binaries and collect results

for binary in *.exe; do
    glaurung ask "$binary" \
        --quick \
        --format jsonl \
        --quiet \
        >> analysis_results.jsonl
done

# Process results with jq
jq -s 'group_by(.binary) | map({binary: .[0].binary, suspicious: any(.results[].answer; contains("malicious"))})' analysis_results.jsonl
```

## Available Analysis Tools

The ask command uses these RE tools automatically:
- **Navigation**: Navigate to addresses, list functions
- **Search**: Search strings, search bytes
- **Analysis**: Analyze functions, check imports, entropy
- **IOC Detection**: Find URLs, IPs, domains, emails
- **Memory**: Examine bytes at addresses

## Tips

1. **Start with broad questions**: "What kind of binary is this?"
2. **Follow up with specifics**: "Show me the suspicious imports"
3. **Use --quick for rapid triage**: Gets common malware indicators
4. **Use JSON for automation**: Easy to parse and process
5. **Use --show-tools for learning**: See how analysis works

## Command Reference

```
usage: glaurung ask [-h] [--format {plain,rich,json,jsonl}] [--no-color]
                    [--quiet] [--verbose] [-a QUESTION |
                    -m QUESTIONS [QUESTIONS ...] | -i | --stdin]
                    [--show-tools] [--show-plan] [--model MODEL]
                    [--max-read-bytes MAX_READ_BYTES]
                    [--max-file-size MAX_FILE_SIZE] [--quick]
                    path

positional arguments:
  path                  Path to binary file to analyze

options:
  -h, --help            show this help message and exit
  --format {plain,rich,json,jsonl}
                        Output format (default: rich)
  --no-color            Disable colored output
  --quiet, -q           Suppress non-essential output
  --verbose, -v         Enable verbose output
  -a, --ask QUESTION    Question to ask about the binary
  -m, --multiple QUESTIONS [QUESTIONS ...]
                        Multiple questions to ask
  -i, --interactive     Interactive Q&A mode
  --stdin               Read questions from stdin
  --show-tools          Show tool calls and results
  --show-plan           Show LLM planning/reasoning
  --model MODEL         Model to use (default: openai:gpt-4.1-mini)
  --max-read-bytes MAX_READ_BYTES
                        Max bytes to read (default: 10MB)
  --max-file-size MAX_FILE_SIZE
                        Max file size (default: 100MB)
  --quick               Quick malware analysis mode
```

## Integration with Other Commands

The ask command complements other Glaurung commands:
- Use `glaurung triage` first for detailed analysis
- Use `glaurung symbols` for symbol-specific queries
- Use `glaurung disasm` for assembly-level details
- Use `glaurung ask` for natural language understanding