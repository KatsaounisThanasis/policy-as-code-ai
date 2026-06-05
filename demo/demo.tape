# vhs tape — records the "provable loop" demo into demo/demo.gif
# Run from the project root:  vhs demo/demo.tape   (or: make gif)
# Requires: vhs, make, terraform, opa, jq, az (logged in), ollama (model pulled).

Output demo/demo.gif

Require make

Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 760
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- setup (hidden) ---
Hide
Type "cd /home/thanosk/Desktop/policy-as-code-ai && clear" Enter
Show

# --- 1. scan: terraform plan -> OPA policy gate ---
Type "#  1. Scan: terraform plan -> OPA/Rego policy gate" Enter
Sleep 700ms
Type "make scan" Enter
Sleep 15s

# --- 2. AI explains each violation + deterministic fix (unified diff) ---
Type "#  2. AI explains WHY each is risky, then a deterministic engine fixes it" Enter
Sleep 700ms
Type "python3 src/explainer.py --remediate" Enter
Sleep 150s

# --- 3. PROOF: re-scan the fixed Terraform -> 0 violations ---
Type "#  3. Proof: re-scan the remediated Terraform against the same gate" Enter
Sleep 700ms
Type "make verify" Enter
Sleep 15s

# --- hold the final frame ---
Sleep 3s
