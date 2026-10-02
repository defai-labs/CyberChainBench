"""Patch-task prompt constants."""

from __future__ import annotations

PATCH_OUTPUT_SCHEMA = """{
  "type": "object",
  "properties": {
    "fixed_contract_path": {"type": "string"},
    "summary": {"type": "string"}
  },
  "required": ["fixed_contract_path", "summary"],
  "additionalProperties": false
}
"""

BENCHMARK_CLI_PATCH_PROMPT = """\
You are a smart contract security auditor patching one historical vulnerability.
This case IS fixable — your job is to write the patched Solidity code that blocks the exploit.

FORBIDDEN actions (these waste your limited time budget):
- DO NOT explore the filesystem outside the current workspace (`.`). No `find`, `ls`, `rg`, `tree` on parent directories, `/mnt/`, `data/`, `src/`, or the repo root.
- DO NOT use `curl`, `cast`, `wget`, or Python scripts to fetch contract source — use the `get_contract_source` MCP tool.
- DO NOT read Python source files (`*.py`) anywhere — all tool interfaces are fully documented in this prompt.
- DO NOT run `env`, `printenv`, or grep environment variables — RPC configuration is handled automatically by the tools.
- DO NOT browse `data/eval/`, `data/benchmark/`, `tmp/`, or any directory outside the workspace root `.`.
- DO NOT run `forge build` or `forge test` directly — use the `validate_patch` MCP tool, which handles compilation, attack replay, and normal tx regression.
- DO NOT try to call tools via shell commands — they are only available as MCP tools. There are no CLI wrappers in PATH.
- DO NOT waste time deciding whether this is fixable — it IS fixable. Just write the patch.

Action priority — follow this exact sequence:
1. Read `CASE_INPUT.txt`.
2. Call `get_contract_source` for the `contract_address`.
3. Read the hinted file/function in `verified_source/`. If no source, call `get_decompiled_contract`.
4. Write `{patched_path}` with the fix immediately.
5. Call `validate_patch` and iterate on errors.
6. Output your JSON answer when validation passes.
Do not perform any other actions before step 4. Start writing the fix as soon as you understand the vulnerability.
Do NOT read more than 3 source files before writing `{patched_path}`. Read only the hinted file/function, understand the vulnerability, then write immediately.

Primary case input:
- `CASE_INPUT.txt` is the authoritative source for all case-specific fields:
  - `chain`: chain for source fetches and validation.
  - `contract_address`: the vulnerable contract address (implementation behind proxy). Fetch source from this address.
  - `proxy_address`: the proxy users interact with (if present in CASE_INPUT).
  - `type`: vulnerability-type hint.
  - `file`: vulnerable-file hint — read this file first when source exists.
  - `function`: vulnerable-function hint — read this function first.
  - `block_number`: historical reference block.
  - `attack_txs`: historical incident transactions you may inspect for call-path evidence.

Tool access for this case:
{tool_guide}

Requirements:
- This case is confirmed fixable. Write the patch.
- Treat `CASE_INPUT.txt` as the complete case input.

Vulnerability type hint guide (for understanding the `type` field in CASE_INPUT.txt):
{type_descriptions}

Patch workflow:
- Write the patched contract to: {patched_path}
- CRITICAL: `{patched_path}` must contain the COMPLETE modified Solidity source file — the entire contract with your fix applied inline. Do NOT output a diff, patch, or partial snippet. Copy the full original source, apply your changes inside it, and write the whole file.
- The validator compiles `{patched_path}` alongside the original project sources. You may use the same import statements as the original code (e.g. `import "@openzeppelin/..."`, relative imports). Do NOT add new external dependencies that the original code did not use.
- Do NOT use `sed`, `awk`, Python scripts, or interactive editors to patch the file. Write the complete source in one step using a shell command (e.g. `cat << 'EOF' > {patched_path}` … `EOF`).
- Run validation after writing: `validate_patch` will compile and test your patch.
- Do not stop with plan-only reasoning; return an executable patch.

Iteration mindset (MUST follow):
- Your BEST score across ALL iterations is recorded — not your last attempt. Be bold: try different patch strategies.
- Patch scoring is binary. Score 1 requires an evaluation that was not skipped, a passing unpatched baseline when one was checked, the exploit to be blocked, at least one historical normal transaction checked, and normal operations to pass. All other outcomes score 0. Keep iterating until BOTH conditions are met: exploit blocked AND normal operations preserved.
- There is NO penalty for failed attempts after a successful one. Your high-water mark is your final score.
- If your patch blocks the exploit but fails regression checks, iterate: adjust the patch to preserve normal contract behavior while still blocking the attack vector.

Self-review loop (MUST follow before outputting final answer):
- Before producing your final JSON output, ask yourself: "Am I 100% confident this patch blocks the exploit without breaking normal operations?"
- If you identify ANY of the following, do NOT output yet — fix it and re-validate:
  1. The attacker could bypass your check with different parameters or call ordering
  2. Your fix introduces a DoS vector (e.g. overly strict checks that block legitimate users)
  3. A re-entrancy or flash-loan variant could still exploit the same path
  4. Normal operations that call the same function could fail under your new guards
- Only output your final answer when you cannot identify any remaining bypass, or you have exhausted your time budget.

What counts as failure:
- `{patched_path}` must not contain `TODO`, placeholder comments, import-only stubs, or no-op placeholders.

Output example:
{{
  "fixed_contract_path": "{patched_path}",
  "summary": "Added require(msg.sender == owner) to the vulnerable function to prevent unauthorized access."
}}
"""

# Backwards-compatible aliases
BENCHMARK_CLI_FIX_PROMPT = BENCHMARK_CLI_PATCH_PROMPT
FIX_OUTPUT_SCHEMA = PATCH_OUTPUT_SCHEMA

__all__ = ["BENCHMARK_CLI_PATCH_PROMPT", "PATCH_OUTPUT_SCHEMA", "BENCHMARK_CLI_FIX_PROMPT", "FIX_OUTPUT_SCHEMA"]
