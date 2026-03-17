<h3 align="center">
wosclaw：基于 OpenClaw 的端云混合大模型调用框架
</h3>

<p align="center">
    【中文 | <a href="./README.md"><b>English</b></a>】
</p>

## 概述

**wosclaw** 是在 **OpenClaw** 基础上构建的项目，旨在支持混合端‑云大模型调用。它通过无缝集成本地（边缘）模型与远程（云）服务，使得在多种部署场景下能够灵活、高效地使用大型模型。

为了解决 AI Agent 数据泄露问题，wosclaw 提供了完整的三级安全体系（S1 直通 / S2 脱敏 / S3 本地），并将安全护栏标准化为通用的 GuardAgent Protocol（Hooker → Detector → Action）。配合智能的端‑云路由能力，开发者无需改动业务代码，即可在 OpenClaw 中实现"公开数据上云、私密数据本地"的无感隐私保护，兼顾模型性能与数据安全。

## 安装

与 OpenClaw 保持一致：

### 1. 克隆仓库

### 2. 安装依赖 + 构建

```bash
pnpm install
pnpm build
pnpm ui:build
pnpm openclaw onboard // 向导配置 openclaw
pnpm openclaw gateway run --verbose // 启动网关
```

### 3. 安装扩展

GuardClaw 已包含在 `extensions/guardclaw` 目录中。请在 `openclaw.json` 配置文件中启用：

<!-- OpenClaw.json Configuration Guidance -->
### OpenClaw.json 配置说明

如需配置 GuardClaw 及其他插件，请编辑 `~/.openclaw/` 目录下的 `openclaw.json` 文件。以下是一个启用 GuardClaw 隐私设置并注册 guard agent 的最简示例：

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

请根据实际安全需求调整 `privacy` 字段。更多高级自定义选项，请参阅 `extensions/guardclaw` 目录下的 README 及 GuardClaw 文档。

### 4. 配置 Guard

在 `openclaw.json` 中编辑 `plugins.entries.guardclaw.config` 的 `privacy` 字段（完整说明见下方 [自定义配置](#自定义配置) 部分）：

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

同时，在 `openclaw.json` 的 `agents` 部分添加 `list` 字段：

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

5. 使用 LM Studio 启动 gpt‑oss‑20b

```bash
# 下载并安装 LM Studio：https://lmstudio.ai，按照安装向导完成安装
# 启动 LM Studio
# 在 LM Studio 中点击 "Add Model"，搜索 "gpt-oss-20b"
# 点击 "Download" 下载模型（需约 40GB 磁盘空间）
# 下载完成后点击 "Serve"，启动本地 OpenAI 兼容服务
# 服务默认运行在 http://localhost:1234
# 在 openclaw.json 中将 endpoint 设置为：
#   "endpoint": "http://localhost:1234/v1"
```

然后正常启动 OpenClaw：

```bash
pnpm openclaw gateway run
```

GuardClaw 将自动拦截并路由敏感请求。

## 自定义配置

GuardClaw 支持自定义配置、规则等：

### JSON 配置 — 规则与模型

在 `openclaw.json` 中编辑 `plugins.entries.guardclaw.config` 的 `privacy` 字段：

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

### 自定义检查点与检测器类型

控制各阶段运行的检测器：

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

- `ruleDetector`：快速规则检测  
- `localModelDetector`：基于本地 LLM 的语义检测（约 1‑2 秒），推荐用于 `onUserMessage`

### 自定义模型

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

支持任何兼容 OpenAI 接口的模型。
