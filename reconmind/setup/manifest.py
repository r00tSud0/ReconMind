"""
Pinned components the installer provides. Versions and SHA-256 digests were
taken from each project's official release checksums file. Change them only
together, after checking the new release's own checksums.
"""

from reconmind.code.semgrep_scan import PINNED_COMMIT as SEMGREP_RULES_COMMIT

SUPPORTED_DISTROS = ("ubuntu", "debian", "kali")
ARCHES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
MIN_PYTHON = (3, 10)
MIN_FREE_BYTES = 3 * 1024 ** 3

# System packages, installed with one sudo apt-get step after the user agrees.
APT_COMMON = ("nmap", "testssl.sh", "dirb", "smbclient", "samba-common-bin", "git", "python3-venv")
# Kali packages every scanning tool, so nothing is downloaded by hand there.
APT_KALI = ("exploitdb", "ffuf", "nuclei", "httpx-toolkit", "enum4linux-ng")

# Release binaries for Ubuntu and Debian. {v} is the version, {a} amd64 or arm64.
RELEASES = {
    "ffuf": {
        "version": "2.3.0",
        "url": "https://github.com/ffuf/ffuf/releases/download/v{v}/ffuf_{v}_linux_{a}.tar.gz",
        "sha256": {
            "amd64": "b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb",
            "arm64": "e2d712615d53da797ee929006e41f2df5a7960a5353133db9c150ddaa22ae4e8",
        },
        "member": "ffuf",
    },
    "nuclei": {
        "version": "3.11.1",
        "url": "https://github.com/projectdiscovery/nuclei/releases/download/v{v}/nuclei_{v}_linux_{a}.zip",
        "sha256": {
            "amd64": "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
            "arm64": "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
        },
        "member": "nuclei",
    },
    # ProjectDiscovery httpx, not the Python package of the same name.
    "httpx": {
        "version": "1.12.0",
        "url": "https://github.com/projectdiscovery/httpx/releases/download/v{v}/httpx_{v}_linux_{a}.zip",
        "sha256": {
            "amd64": "9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76",
            "arm64": "fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e",
        },
        "member": "httpx",
    },
}

# Git sources for Ubuntu and Debian. commit None means the newest commit of
# ref is taken (Exploit-DB changes daily); the commit used is logged.
EXPLOITDB = {"url": "https://gitlab.com/exploit-database/exploitdb.git", "ref": "main",
             "commit": None}
ENUM4LINUX_NG = {"url": "https://github.com/cddmp/enum4linux-ng.git", "ref": "v1.3.10",
                 "commit": "f34e7bb3bc2bcd10267a7257fb3658154434ccf4"}
SEMGREP_RULES = {"url": "https://github.com/semgrep/semgrep-rules.git",
                 "commit": SEMGREP_RULES_COMMIT}

# Used only when "nuclei -update-templates" cannot record a templates version
# (it exits 0 even when GitHub's API is unreachable).
NUCLEI_TEMPLATES = {"url": "https://github.com/projectdiscovery/nuclei-templates.git",
                    "ref": "v10.5.2", "commit": "5442582a875f96887bfe403c6de562de460897e7"}

# Python programs, each in its own environment so their pins never clash
# with the app's packages (Semgrep's opentelemetry pin clashes with FastAPI).
PIP_TOOLS = {"semgrep": "semgrep==1.185.0", "bandit": "bandit==1.9.4"}

# The fine tuned SciBERT Run 3 ATT&CK mapper, from the project's own GitHub
# Release (tag model-run3-v1). url, sha256 and size are the published asset's,
# checked by downloading it on 18 Nov 2026.
MODEL = {
    "url": "https://github.com/r00tSud0/ReconMind/releases/download/model-run3-v1/attack_mapper_run3.tar.gz",
    "sha256": "6ce8ca961388546f8779a382e454b3775a3d5cddf4b6a812d5d1fdb4ad128a23",
    "size": 409970311,
    "folder": "attack_mapper_run3",
    "labels": 394,
}
# Packages the mapper needs inside the app's own Python environment.
MAPPER_TORCH_INDEX = "https://download.pytorch.org/whl/cpu"
MAPPER_PACKAGES = ("torch", "transformers==5.22.1", "safetensors")
