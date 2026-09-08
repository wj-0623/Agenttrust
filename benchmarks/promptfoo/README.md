# Promptfoo external benchmark adapter

This configuration runs a small deterministic smoke benchmark through AgentTrust's public Gateway API. It is intentionally separate from the built-in evaluation set so reviewers can reproduce the result with an independent runner.

```powershell
# Terminal 1: start AgentTrust on loopback
cd backend
python -m uvicorn app.main:app --port 8010

# Terminal 2: run from this directory
npx promptfoo@0.122.2 eval -c promptfooconfig.yaml --no-cache \
  --output results.json --output report.html
```

The committed `results.json` and `report.html` are reproducible release-candidate evidence generated with Promptfoo 0.122.2. Do not treat four smoke cases as a security-accuracy claim. For a public benchmark claim, also record the AgentTrust Git SHA and run a larger frozen dataset with a real model target. Promptfoo file providers and executable assertions are trusted local code rather than a sandbox, so only run reviewed configurations.

Reference: <https://github.com/promptfoo/promptfoo/blob/main/site/docs/red-team/configuration.md>
