# ReconMind

**An AI security analyst agent that runs reconnaissance, finds vulnerabilities, classifies malware, and writes attack-path reports.**

---

## What ReconMind Does

You hand ReconMind one of three things. It figures out what it was given, runs the right tools, and writes one report. There are three jobs it can do.

**1. You give it a target (an IP on your lab network)**

The agent scans the machine and maps it out. It finds the open ports, identifies the service and version on each one, looks up the known vulnerabilities for those versions, and checks any web services for hidden pages and weak encryption. Then it explains how those weaknesses could be chained into an attack path.

**2. You give it a file (a suspected malware sample)**

The agent runs it through a malware classifier that was trained on thousands of real malware images. It returns which malware family the file belongs to and how confident it is, then writes a short note on what that family typically does.

**3. You give it code (a source file)**

The agent reads the code and flags the functions that look vulnerable, such as SQL injection or hardcoded passwords, and explains why each one is a risk.

Whatever the job, the result is the same kind of output: a clear report with the findings, how severe they are, the matching MITRE ATT&CK techniques, and the attack path or explanation.

It runs only against systems the user owns or is authorized to test, enforced in code before any scan.

## How Many AIs Are in the System

Three AI components, each with a different job.

1. **The agent brain**: a large language model (used through its API) that reads your input, decides which tools to run and in what order, reads each result, and writes the final report. This same model also reads code for the code-analysis job. It is not trained by us, it is prompted.

2. **The ATT&CK mapper**: a small model that we fine-tune ourselves to tag each finding with its MITRE ATT&CK technique. We compare it against a large prompted model to measure whether the fine-tuning helped. This is the project's core AI experiment.

3. **The malware classifier**: a convolutional neural network (CNN) that we build and train from scratch to identify the malware family of a sample from its image.

In short: one LLM runs the whole workflow and writes the reports, and two models we train ourselves handle the ATT&CK tagging and the malware classification.

## The Tools the Agent Uses

- **rustscan**: fast first pass to find which ports are open.
- **nmap**: identifies the service and version on each open port and runs built-in vulnerability scripts.
- **whatweb**: fingerprints a web server's technology stack (server, CMS, framework).
- **ffuf**: finds hidden directories and files on a web server.
- **nuclei**: template-based scanner that checks a target against a large library of known vulnerabilities.
- **testssl.sh**: checks a site's HTTPS for weak or outdated encryption.
- **enum4linux-ng**: pulls users, shares, and info out of Windows and SMB services.
- **searchsploit**: offline database that matches a service version to known public exploits.
- **Vulners / NVD**: live databases queried for the CVEs affecting a given version.

Every tool is a plug-in module with a fixed input and output, so tools can be added, swapped, or chained without touching the agent.

## How the Agent Thinks

ReconMind uses the ReAct pattern (Reason, Act, Observe, repeat). The agent brain reasons about what to do, runs a tool, reads the result, and reasons again, until it has enough to report. It does not run everything blindly. It decides the next tool based on what the last one found.

## Running It

Run from the repo root on the Kali attacker box (nmap and searchsploit come with Kali).

```bash
pip install -r requirements.txt
echo 'ANTHROPIC_API_KEY=sk-ant-...' > .env      # .env is gitignored

python3 -m reconmind.agent 10.10.1.100           # LLM agent: ReAct loop picks the tools
python3 -m reconmind.recon 10.10.1.100           # fixed pipeline, no LLM
python3 -m unittest tests.test_agent -v          # offline tests, no key or network needed
```

The agent prints its live trace (THOUGHT, ACTION, OBSERVE) and writes a Markdown report to `reports/` with its analyst summary on top of the raw tool tables.

Safety is layered. The target is checked by the authorization gate before the model is called at all. Inside the run, the model can only request tools from a fixed list, every request is held to the single target the operator typed (scope lock), and each tool runs the gate again before launching anything. The loop has a hard step limit.

## Data Sources

- MITRE ATT&CK and the MITRE TRAM dataset, used to fine-tune the ATT&CK mapper.
- NVD / CVE and Vulners, queried live for known vulnerabilities.
- Malimg dataset (malware samples as grayscale images), used to train the malware CNN.
- CVEfixes (real vulnerable and fixed code pairs), for the code-analysis module.
- Scan targets are local, deliberately vulnerable lab systems (Metasploitable 2, DVWA).

## Technology Stack

- Language: Python
- Agent: the LLM provider SDK, tool-calling, ReAct pattern
- Training: both trained models use PyTorch on a Google Colab GPU. The malware CNN is built from scratch; the ATT&CK mapper is fine-tuned from a pretrained model using Hugging Face, which runs on PyTorch.
- Interface: a terminal UI built with rich / textual
- Security tools: rustscan, nmap, whatweb, ffuf, nuclei, testssl.sh, enum4linux-ng, searchsploit
- Environment: WSL2 Ubuntu runs the agent and tools, with VirtualBox lab targets

## Development Plan

- Stage 1: agent shell, authorization gate, nmap recon on the lab VM, report builder.
- Stage 2: web app chain, enumeration, CVE lookup, ATT&CK mapper (prompted first).
- Stage 3: fine-tune the ATT&CK mapper and measure it against a prompted large model.
- Stage 4: the code-vulnerability module and the malware classifier CNN.

## Ethics and Authorization

ReconMind is for authorized security testing only. It runs exclusively against systems the user owns or has written permission to test. An authorization gate checks every target against an allowlist in code and refuses, and logs, anything out of scope. Scanning without authorization is illegal, and this project must never be used for that.