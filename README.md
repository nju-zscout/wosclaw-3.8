
<h3 align="center">
wosclaw: Hybrid Edge‑Cloud Large‑Model Invocation Framework based on OpenClaw
</h3>

<p align="center">
    【<a href="./readme_zh.md"><b>中文</b></a> | English】
</p>

## Overview

**wosclaw** is a project built on top of **OpenClaw**, designed to support hybrid edge‑cloud large‑model invocation. It extends OpenClaw’s capabilities by allowing seamless integration of local (edge) models with remote (cloud) services, enabling flexible, high‑performance AI applications across diverse deployment scenarios.

Designed to tackle the AI Agent data leakage challenge, wosclaw provides a comprehensive, customizable three‑tier security system (S1 passthrough / S2 desensitization / S3 local). It standardizes safety guardrails into a universal GuardAgent Protocol (Hooker → Detector → Action). Combined with intelligent edge‑cloud routing capabilities, developers can achieve seamless privacy protection — “public data to the cloud, private data stays local” — within OpenClaw without modifying any business logic, balancing the peak performance of large models with absolute security of sensitive data.


## Installation

Same as OpenClaw:

### 1. Clone the Repository

### 2. Install Dependencies + Build

```bash
pnpm install
pnpm build
pnpm ui:build
pnpm openclaw onboard // a wizard to config openclaw
pnpm openclaw gateway run --verbose // start gateway
```

### 3. Install the Extension

GuardClaw is included in the `extensions/guardclaw` directory. Enable it in your `openclaw.json` configuration:

<!-- OpenClaw.json Configuration Guidance -->
### OpenClaw.json Configuration Guidance

To configure GuardClaw and other plugins, edit the `openclaw.json` file under `~/.openclaw/`. Below is a minimal example that enables GuardClaw with privacy settings and registers the guard agent:

```json
{
  "plugins": {
    "entries": {
      "guardclaw": {
        "enabled": true,
        "config": {
          "privacy": {
            "enabled": true,
            "localModel": {
              "enabled": true,
              "provider": "openai",
              "model": "openai/gpt-oss-20b",
              "endpoint": "http://localhost:1234/v1"
            },
            "guardAgent": {
              "id": "guard",
              "workspace": "~/.openclaw/workspace-guard",
              "model": "openai/gpt-oss-20b"
            }
          }
        }
      }
    }
  },
  "agents": {
    "list": [
      {
        "id": "main",
        "workspace": "~/.openclaw/workspace-main",
        "subagents": {
          "allowAgents": ["guard"]
        }
      },
      {
        "id": "guard",
        "workspace": "~/.openclaw/workspace-guard",
        "model": "openai/gpt-oss-20b"
      }
    ]
  }
}
```

Adjust the `privacy` fields to match your security requirements. For more advanced customization, see the `extensions/guardclaw` README and the GuardClaw documentation.

### 4. Configure Guard

Edit the `privacy` field under `plugins.entries.guardclaw.config` in `openclaw.json` (see the [Customization](#customization) section below for full details):

```json
{
  "privacy": {
    "enabled": true,
    "localModel": {
      "enabled": true,
      "provider": "openai",
      "model": "openai/gpt-oss-20b",
      "endpoint": "http://localhost:1234/v1"
    },
    "guardAgent": {
      "id": "guard",
      "workspace": "~/.openclaw/workspace-guard",
      "model": "openai/gpt-oss-20b"
    }
  }
}
```

Also, add a `list` field under the `agents` section in `openclaw.json`:

```json
"list": [
  {
    "id": "main",
    "workspace": "~/.openclaw/workspace-main",
    "subagents": {
      "allowAgents": ["guard"]
    }
  },
  {
    "id": "guard",
    "workspace": "~/.openclaw/workspace-guard",
    "model": "openai/gpt-oss-20b"
  }
]
```

5. Start LM Studio with gpt-oss-20b

```bash
# Install LM Studio (download from https://lmstudio.ai and follow the installer)
# Launch LM Studio
# In LM Studio, click "Add Model" → search for "gpt-oss-20b"
# Click "Download" to fetch the model (requires ~40GB disk space)
# After download, click "Serve" to start a local OpenAI‑compatible server
# The server runs on http://localhost:1234 by default
# Set the endpoint in your `openclaw.json` to:
#   "endpoint": "http://localhost:1234/v1"
```

Then start OpenClaw as usual:

```bash
pnpm openclaw gateway run
```

GuardClaw will automatically intercept and route sensitive requests.

## Customization

GuardClaw supports custom configuration, rules, and more:

### JSON Configuration — Rules & Models

Edit the `privacy` field under `plugins.entries.guardclaw.config` in `openclaw.json`:

```json
{
  "privacy": {
    "rules": {
      "keywords": {
        "S2": ["password", "api_key", "token", "credential"],
        "S3": ["ssh", "id_rsa", "private_key", ".pem", "master_password"]
      },
      "patterns": {
        "S2": [
          "\\b(?:10|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3}\\b",
          "(?:mysql|postgres|mongodb)://[^\\s]+"
        ],
        "S3": ["-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "AKIA[0-9A-Z]{16}"]
      },
      "tools": {
        "S2": {
          "tools": ["exec", "shell"],
          "paths": ["~/secrets", "~/private"]
        },
        "S3": {
          "tools": ["system.run", "sudo"],
          "paths": ["~/.ssh", "/etc", "~/.aws", "/root"]
        }
      }
    }
  }
}
```

### Custom Checkpoints & Detector Types

Control which detectors run at which stage:

```json
{
  "privacy": {
    "checkpoints": {
      "onUserMessage": ["ruleDetector", "localModelDetector"],
      "onToolCallProposed": ["ruleDetector"],
      "onToolCallExecuted": ["ruleDetector"]
    }
  }
}
```

- `ruleDetector` — Fast rule‑based detection  
- `localModelDetector` — LLM‑based semantic understanding (~1–2 s), recommended for `onUserMessage`

### Custom Models

```json
{
  "privacy": {
    "localModel": {
      "enabled": true,
      "provider": "openai",
      "model": "openai/gpt-oss-20b",
      "endpoint": "http://localhost:1234/v1"
    },
    "guardAgent": {
      "id": "guard",
      "workspace": "~/.openclaw/workspace-guard",
      "model": "openai/gpt-oss-20b"
    }
  }
}
```

Any openai‑compatible model is supported.
