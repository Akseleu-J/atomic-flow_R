# Atomic Flow — engineer beta quickstart

Your beta pass is **96 hours** from first activation. `af beta` shows the
remaining time at any moment. Everything runs **on your machine** (self-host):
your provider key stays with you, your project never leaves your disk, and the
only network traffic is the model API you configure and the pass check.

## 1. Install

1. Download the archive for your OS from your personal invitation link, and
   the `SHA256SUMS.txt` next to it.
2. Verify the hash, then extract into a **new empty directory**:

```bash
# Linux
sha256sum -c SHA256SUMS.txt
unzip atomic-flow-beta-<os>.zip -d atomic-flow-beta
cd atomic-flow-beta
chmod +x ./af   # if your extractor did not preserve permissions
```

```powershell
# Windows PowerShell
Get-FileHash .\atomic-flow-beta-<os>.zip   # compare with SHA256SUMS.txt
Expand-Archive .\atomic-flow-beta-<os>.zip -DestinationPath .\atomic-flow-beta
cd .\atomic-flow-beta
```

3. Run the doctor — every line should end in PASS:

```bash
./af doctor          # Linux   |   .\af.exe doctor   # Windows
```

## 2. First run (10 minutes)

1. Start Studio (loopback only, stop with Ctrl+C):

```bash
./af serve --studio-dist studio     # open http://127.0.0.1:8787/studio/
```

2. Register a workspace: pick your project folder in the Studio settings.
3. Your provider key stays in your environment: choose a supported provider
   and model in Studio, then set a spending ceiling:

```bash
af budget create --cap-usd 1.00 --max-calls 64
af budget show
```

4. The main scenario — give Atomic Flow a task on your own repo:

```bash
af task run --root-id <root> --file <path/to/file> \
  --replacement "<exact reviewed replacement text>" \
  --provider-id <provider> --model <model> \
  --budget-cap-usd 0.50 \
  --check-argv <cmd> --junit <report.xml>
```

FAIL leaves your source untouched; PASS applies exactly the reviewed bytes.
A refused or held budget is the safety system working — the run simply stops.

## 3. Feedback

After any problem — and once at the end of your window — export one package:

```bash
af evidence export
```

Attach the resulting `af-evidence-<session>.json` to your forum thread.
It contains event skeletons, doctor output and the version — **no source
code, no prompts, no keys** unless you explicitly pass `--include-payloads`.

## Safety model

- Edits require a reviewed plan; verification without an admitted checker
  ends `Unverified` and never auto-commits.
- Unknown model cost = durable HOLD; nothing replays until you reconcile.
- Unknown crashes: `af` writes a local crash log and `af evidence export`
  includes its summary — nothing is sent anywhere by itself.
