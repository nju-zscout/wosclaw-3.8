/**
 * GuardClaw Hooks Registration
 *
 * Registers all plugin hooks for sensitivity detection at various checkpoints.
 * Implements:
 *   - S1: pass-through (no intervention)
 *   - S2: desensitize content via local model / rules, then forward to cloud
 *   - S3: redirect to isolated guard subsession with local-only model
 *   - Dual session history (full vs clean)
 *   - Memory isolation (MEMORY-FULL.md vs MEMORY.md)
 *   - File-access guards (block cloud models from reading full history/memory)
 */

import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { stringify } from "node:querystring";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { defaultPrivacyConfig } from "./config-schema.js";
import { detectSensitivityLevel } from "./detector.js";
import {
  generateGuardSessionKey,
  isGuardSessionKey,
  getGuardAgentConfig,
  buildMainSessionPlaceholder,
  isLocalProvider,
} from "./guard-agent.js";
import { desensitizeWithLocalModel, callLocalModelDirect } from "./local-model.js";
import { getDefaultMemoryManager } from "./memory-isolation.js";
import { loadPrompt } from "./prompt-loader.js";
import { getDefaultSessionManager, type SessionMessage } from "./session-manager.js";
import {
  markSessionAsPrivate,
  recordDetection,
  isSessionMarkedPrivate,
  getSessionSensitivity,
  markPreReadFiles,
  isFilePreRead,
} from "./session-state.js";
import type { PrivacyConfig } from "./types.js";
import { redactSensitiveInfo, isProtectedMemoryPath } from "./utils.js";

/**
 * Default guard agent system prompt (used as fallback if prompts/guard-agent-system.md is missing).
 * To customize, edit: extension/prompts/guard-agent-system.md
 */
const DEFAULT_GUARD_AGENT_SYSTEM_PROMPT = `You are a privacy-aware analyst. Analyze the data the user provides. Do your job.

RULES:
1. Analyze the data directly. Do NOT write code. Do NOT generate programming examples or tutorials.
2. NEVER echo raw sensitive values (exact salary, SSN, bank account, password). Use generic references like "your base salary", "the SSN on file", etc.
3. You MAY discuss percentages, ratios, whether deductions are correct, anomalies, and recommendations.
4. Reply ONCE, then stop. No [message_id:] tags. No multi-turn simulation.
5. **Language rule: Reply in the SAME language the user writes in.** If the user writes in Chinese, reply entirely in Chinese. If the user writes in English, reply entirely in English.
6. Be concise and professional.

语言规则：必须使用与用户相同的语言回复。如果用户用中文提问，你必须用中文回答。`;

/** Load guard agent system prompt from prompts/guard-agent-system.md (or use default) */
function getGuardAgentSystemPrompt(): string {
  return loadPrompt("guard-agent-system", DEFAULT_GUARD_AGENT_SYSTEM_PROMPT);
}

/**
 * Register all GuardClaw hooks
 */
export function registerHooks(api: OpenClawPluginApi): void {
  // Conditionally intercept globalThis.fetch to log LLM request/response bodies to disk.
  // Only enabled when privacy.debug.interceptLlmRequests = true in plugin config.
  // WARNING: This writes all LLM payloads (including sensitive content) to disk.
  // Never enable in production.
  const privacyConfigForDebug = getPrivacyConfigFromApi(api);
  if (privacyConfigForDebug.debug?.interceptLlmRequests === true) {
    if (!(globalThis as any).__fetchIntercepted) {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async (...args: Parameters<typeof fetch>) => {
        const url = args[0] as string | URL | Request;
        const opts = args[1] as RequestInit | undefined;
        const urlString = url.toString();
        const reqId = Date.now();
        const isLLM =
          urlString.includes("v1/chat/completions") ||
          urlString.includes("anthropic") ||
          urlString.includes("googleapis.com/v1/models");

        if (isLLM) {
          try {
            if (opts?.body) {
              let bodyStr =
                opts.body instanceof Uint8Array || Buffer.isBuffer(opts.body)
                  ? new TextDecoder().decode(opts.body as Uint8Array)
                  : opts.body.toString();
              const bodyJson = JSON.parse(bodyStr);
              // oxlint-disable-next-line typescript/no-require-imports
              const fs = require("node:fs") as typeof import("node:fs");
              // oxlint-disable-next-line typescript/no-require-imports
              const nodePath = require("node:path") as typeof import("node:path");
              const reqFileName = nodePath.join(
                process.cwd(),
                `llm_request_body_${reqId}.json`,
              );
              fs.writeFileSync(reqFileName, JSON.stringify(bodyJson, null, 2), "utf8");
              api.logger.info(
                `[GuardClaw][debug] LLM request body written to: ${reqFileName}`,
              );
            }
          } catch (e) {
            api.logger.error(`[GuardClaw][debug] Failed to write request body: ${String(e)}`);
          }
        }

        const response = await originalFetch(...args);

        if (isLLM) {
          try {
            const resClone = response.clone();
            // oxlint-disable-next-line typescript/no-require-imports
            const fs = require("node:fs") as typeof import("node:fs");
            // oxlint-disable-next-line typescript/no-require-imports
            const nodePath = require("node:path") as typeof import("node:path");
            const resText = await resClone.text();
            const resFileName = nodePath.join(process.cwd(), `llm_response_body_${reqId}.txt`);
            fs.writeFileSync(resFileName, resText, "utf8");
            api.logger.info(
              `[GuardClaw][debug] LLM response body written to: ${resFileName}`,
            );
          } catch (e) {
            api.logger.error(
              `[GuardClaw][debug] Failed to write response body: ${String(e)}`,
            );
          }
        }

        return response;
      };
      (globalThis as any).__fetchIntercepted = true;
      api.logger.warn(
        "[GuardClaw][debug] LLM request interception ENABLED — all LLM payloads will be written to disk. Do NOT use in production.",
      );
    }
  }

  // Initialize memory directories on startup
  const memoryManager = getDefaultMemoryManager();
  memoryManager.initializeDirectories().catch((err) => {
    api.logger.error(`[GuardClaw] Failed to initialize memory directories: ${String(err)}`);
  });

  // =========================================================================
  // Hook 1: message_received — Checkpoint for user messages
  // =========================================================================
  api.on("message_received", async (event, ctx) => {
    try {
      api.logger.debug(
        `[GuardClaw] message_received hook triggered with event: ${JSON.stringify(event)}`,
      );
      api.logger.debug(
        `[GuardClaw] message_received hook triggered with ctx: ${JSON.stringify(ctx)}`,
      );

      // Extract message content from event (may be in different fields)
      const messageContent = (event as any).content || (event as any).message;
      const sessionKey = ctx.sessionKey ?? (event as any).sessionKey ?? "default-session";
      const agentId = ctx.agentId ?? (event as any).agentId;

      api.logger.debug(
        `[GuardClaw] message_received: message=${messageContent}, sessionKey=${sessionKey}, agentId=${agentId}`,
      );
      if (!messageContent || !sessionKey) {
        api.logger.error(`[GuardClaw] message_received: missing content or sessionKey, skipping`);
        return;
      }

      const messageText = extractMessageText(messageContent);
      if (!messageText) {
        api.logger.error(
          `[GuardClaw] message_received: unable to extract text from message content, skipping`,
        );
        return;
      }
      api.logger.debug(`[GuardClaw] message_received: extracted messageText=${messageText}`);
      // Detect sensitivity level
      const result = await detectSensitivityLevel(
        {
          checkpoint: "onUserMessage",
          message: messageText,
          sessionKey,
          agentId,
        },
        api.pluginConfig,
        api.logger,
      );

      // Record detection
      recordDetection(sessionKey, result.level, "onUserMessage", result.reason);

      if (result.level !== "S1") {
        api.logger.info(
          `[GuardClaw] message_received Message sensitivity: ${result.level} for session ${sessionKey} — ${result.reason ?? "no reason"}`,
        );
      }

      // Persist to dual history
      const sessionManager = getDefaultSessionManager();
      const sessionMessage: SessionMessage = {
        role: "user",
        content: messageText,
        timestamp: Date.now(),
        sessionKey,
      };
      await sessionManager.persistMessage(sessionKey, sessionMessage, agentId ?? "main");

      // Mark session state
      if (result.level === "S3") {
        markSessionAsPrivate(sessionKey, result.level);
        api.logger.warn(`[GuardClaw] Session ${sessionKey} marked as PRIVATE (S3 detected)`);
      } else if (result.level === "S2") {
        markSessionAsPrivate(sessionKey, result.level);
        api.logger.info(
          `[GuardClaw] S2 detected for session ${sessionKey}. Content will be desensitized for cloud.`,
        );
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in message_received hook: ${String(err)}`);
    }

    api.logger.debug(`[GuardClaw] message_received hook completed`);
  });

  // =========================================================================
  // Hook 2: before_tool_call — Checkpoint for tool calls before execution
  //   S3 tools → BLOCK the call and return an error
  //   S2 tools → allow but log
  //   Also: block cloud model access to protected memory/history paths
  //   Also: guard subagent spawn / A2A send (sessions_spawn, sessions_send)
  // =========================================================================
  api.on("before_tool_call", async (event, ctx) => {
    try {
      const { toolName, params } = event;
      const sessionKey = ctx.sessionKey ?? "";

      if (!toolName) {
        return;
      }

      // ── File-access guard: block cloud models from reading full history / memory ──
      const typedParams = params as Record<string, unknown>;
      if (typedParams) {
        const privacyConfig = getPrivacyConfigFromApi(api);
        const baseDir = privacyConfig.session?.baseDir ?? "~/.openclaw";
        const pathValues = extractPathValuesFromParams(typedParams);

        // If the session is NOT a guard session (i.e., cloud model context),
        // block access to protected full-history / full-memory paths.
        if (!isGuardSessionKey(sessionKey)) {
          for (const p of pathValues) {
            if (isProtectedMemoryPath(p, baseDir)) {
              api.logger.warn(
                `[GuardClaw] BLOCKED: cloud model tried to access protected path: ${p}`,
              );
              return {
                block: true,
                blockReason: `GuardClaw: access to full history/memory is restricted for cloud models (${p})`,
              };
            }
          }
        }
      }

      // ── Block tool reads for files already pre-read in S2 desensitization ──
      if (toolName === "read" || toolName === "read_file" || toolName === "cat") {
        const filePath = String(
          typedParams?.path ?? typedParams?.file ?? typedParams?.target ?? "",
        );
        if (filePath && isFilePreRead(sessionKey, filePath)) {
          api.logger.info(
            `[GuardClaw] BLOCKED tool ${toolName} for pre-read file: ${filePath} (content already desensitized in prompt)`,
          );
          return {
            block: true,
            blockReason: `File content has already been provided in the conversation (desensitized for privacy). No need to read it again.`,
          };
        }
      }

      // ── Subagent / A2A guard ──
      // sessions_spawn: scan the task for sensitivity before it reaches the subagent
      // sessions_send:  scan the message for sensitivity before A2A delivery
      const isSpawn = toolName === "sessions_spawn";
      const isSend = toolName === "sessions_send";

      if (isSpawn || isSend) {
        const contentField = isSpawn
          ? String(typedParams?.task ?? "")
          : String(typedParams?.message ?? "");

        if (contentField.trim()) {
          const subagentResult = await detectSensitivityLevel(
            {
              checkpoint: "onToolCallProposed",
              message: contentField,
              toolName,
              toolParams: typedParams,
              sessionKey,
              agentId: ctx.agentId,
            },
            api.pluginConfig,
            api.logger,
          );

          const label = isSpawn ? "subagent task" : "A2A message";
          recordDetection(
            sessionKey,
            subagentResult.level,
            "onToolCallProposed",
            subagentResult.reason,
          );

          if (subagentResult.level === "S3") {
            const spawnModel = String(typedParams?.model ?? "");
            const isTargetSafe =
              spawnModel.includes("ollama/") ||
              spawnModel.includes("llama") ||
              isLocalProvider(spawnModel.split("/")[0]);

            if (isTargetSafe) {
              api.logger.info(
                `[GuardClaw] Allowed S3 task for sub-agent because it is using a local/safe model (${spawnModel}).`,
              );
              // We return the original params here to skip the "general" sensitivity detection below which will block it
              return { params: typedParams };
            } else {
              markSessionAsPrivate(sessionKey, subagentResult.level);
              api.logger.warn(
                `[GuardClaw] BLOCKED ${toolName}: ${label} contains S3 content. ` +
                  `Reason: ${subagentResult.reason ?? "private data detected"}`,
              );
              return {
                block: true,
                blockReason:
                  `GuardClaw: ${label} blocked — S3 sensitivity detected in ${toolName} ` +
                  `(${subagentResult.reason ?? "private data must not leave local boundary"})`,
              };
            }
          }

          if (subagentResult.level === "S2") {
            markSessionAsPrivate(sessionKey, subagentResult.level);
            api.logger.info(
              `[GuardClaw] S2 detected in ${toolName} ${label}. Desensitizing before forwarding.`,
            );

            const privacyConfig = getPrivacyConfigFromApi(api);
            const { desensitized } = await desensitizeWithLocalModel(contentField, privacyConfig);

            // Return modified params with desensitized content
            const fieldName = isSpawn ? "task" : "message";
            return {
              params: { ...typedParams, [fieldName]: desensitized },
            };
          }

          // S1: fall through to normal detection below
        }
      }

      // ── Sensitivity detection (general) ──
      const result = await detectSensitivityLevel(
        {
          checkpoint: "onToolCallProposed",
          toolName,
          toolParams: typedParams,
          sessionKey,
          agentId: ctx.agentId,
        },
        api.pluginConfig,
        api.logger,
      );

      recordDetection(sessionKey, result.level, "onToolCallProposed", result.reason);

      if (result.level !== "S1") {
        api.logger.info(
          `[GuardClaw] Tool call sensitivity: ${result.level} for ${toolName} — ${result.reason ?? "no reason"}`,
        );
      }

      // S3 → BLOCK the tool call
      if (result.level === "S3") {
        markSessionAsPrivate(sessionKey, result.level);
        api.logger.warn(
          `[GuardClaw] BLOCKED tool ${toolName} (S3). Session ${sessionKey} marked as PRIVATE.`,
        );
        return {
          block: true,
          blockReason: `GuardClaw: tool "${toolName}" blocked — S3 sensitivity detected (${result.reason ?? "sensitive operation"})`,
        };
      }

      // S2 → allow but mark session
      if (result.level === "S2") {
        markSessionAsPrivate(sessionKey, result.level);
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_tool_call hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 3: after_tool_call — Checkpoint for tool results
  // =========================================================================
  api.on("after_tool_call", async (event, ctx) => {
    try {
      const { toolName, result } = event;
      const sessionKey = ctx.sessionKey ?? "";

      if (!toolName) {
        return;
      }

      const detectionResult = await detectSensitivityLevel(
        {
          checkpoint: "onToolCallExecuted",
          toolName,
          toolResult: result,
          sessionKey,
          agentId: ctx.agentId,
        },
        api.pluginConfig,
        api.logger,
      );

      recordDetection(
        sessionKey,
        detectionResult.level,
        "onToolCallExecuted",
        detectionResult.reason,
      );

      if (detectionResult.level !== "S1") {
        api.logger.info(
          `[GuardClaw] Tool result sensitivity: ${detectionResult.level} for ${toolName} — ${detectionResult.reason ?? "no reason"}`,
        );
      }

      if (detectionResult.level === "S3" || detectionResult.level === "S2") {
        markSessionAsPrivate(sessionKey, detectionResult.level);
        if (detectionResult.level === "S3") {
          api.logger.warn(
            `[GuardClaw] Tool ${toolName} result contains S3 content. Session ${sessionKey} marked as PRIVATE.`,
          );
        }
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_tool_call hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 4: tool_result_persist — Control dual-history persistence
  // =========================================================================
  api.on("tool_result_persist", (event, ctx) => {
    try {
      const { message, sessionKey } = event;
      const isPrivate = isSessionMarkedPrivate(sessionKey ?? "");

      if (isPrivate && sessionKey) {
        // Persist to full history (includes everything)
        const sessionManager = getDefaultSessionManager();
        const msgText = typeof message === "string" ? message : JSON.stringify(message);
        const sessionMessage: SessionMessage = {
          role: "tool",
          content: msgText,
          timestamp: Date.now(),
          sessionKey,
        };
        // Fire-and-forget async write
        sessionManager.persistMessage(sessionKey, sessionMessage).catch((err) => {
          console.error(`[GuardClaw] Failed to persist tool result to dual history:`, err);
        });

        api.logger.debug(
          `[GuardClaw] Tool result in private session ${sessionKey}, dual history write triggered`,
        );
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in tool_result_persist hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 5: session_end — Cleanup and memory sync
  // =========================================================================
  api.on("session_end", async (event, ctx) => {
    try {
      const { sessionKey } = event;

      if (sessionKey) {
        const wasPrivate = isSessionMarkedPrivate(sessionKey);
        const sessionType = wasPrivate ? "private (local)" : "cloud";

        api.logger.info(`[GuardClaw] ${sessionType} session ${sessionKey} ended. Syncing memory…`);

        // Always sync: merges cloud MEMORY.md additions into MEMORY-FULL.md,
        // then sanitizes FULL → CLEAN (guard strip + PII redact).
        // This ensures cloud memory always contains sanitized local knowledge,
        // and local memory always captures cloud additions.
        const memMgr = getDefaultMemoryManager();
        const privacyConfig = getPrivacyConfigFromApi(api);
        await memMgr.syncAllMemoryToClean(privacyConfig);

        // Note: We keep session state for audit purposes
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in session_end hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 6: resolve_model — Model + session routing
  //
  //   S1 → pass-through (cloud model, normal session)
  //   S2 → desensitize content, send desensitized version to cloud model
  //   S3 → redirect to guard subsession with local-only model
  // =========================================================================
  api.on("resolve_model", async (event, ctx) => {
    try {
      //05:10:12 [gateway] [GuardClaw] resolve_model hook triggered with event: {"message":"分析excel 文件 D:\\workspace\\privacy\\test.xlsx","provider":"minimax-portal","model":"MiniMax-M2.5","isDefault":true}
      //05:10:12 [gateway] [GuardClaw] resolve_model hook triggered with ctx: {"agentId":"main","sessionKey":"agent:main:main","messageProvider":"webchat"}
      api.logger.debug(
        `[GuardClaw] resolve_model hook triggered with event: ${JSON.stringify(event)}`,
      );
      api.logger.debug(`[GuardClaw] resolve_model hook triggered with ctx: ${JSON.stringify(ctx)}`);
      const { message, provider, model } = event;
      const sessionKey = ctx.sessionKey ?? "";

      api.logger.info(
        `[GuardClaw] resolve_model called: sessionKey=${sessionKey}, message=${String(message).slice(0, 50)}, provider=${provider}, model=${model}`,
      );

      if (!sessionKey) {
        api.logger.error(`[GuardClaw] resolve_model: no sessionKey, returning`);
        return;
      }

      const privacyConfig = getPrivacyConfigFromApi(api);
      api.logger.info(
        `[GuardClaw] resolve_model: enabled=${privacyConfig.enabled}, localModel=${privacyConfig.localModel?.enabled}, checkpoints=${JSON.stringify(privacyConfig.checkpoints?.onUserMessage)}`,
      );
      if (!privacyConfig.enabled) {
        api.logger.error(`[GuardClaw] resolve_model: privacy disabled, returning`);
        return;
      }

      // If already in a guard session, enforce exact local model from config
      if (isGuardSessionKey(sessionKey)) {
        const guardCfg = getGuardAgentConfig(privacyConfig);
        if (guardCfg && (provider !== guardCfg.provider || model !== guardCfg.modelName)) {
          return {
            provider: guardCfg.provider,
            model: guardCfg.modelName,
            reason: `GuardClaw: guard session must use configured local model (${guardCfg.provider}/${guardCfg.modelName})`,
          };
        }
        return; // already correct
      }

      // Detect sensitivity of current message
      if (!message) {
        api.logger.error(`[GuardClaw] resolve_model: no message, return`);
        return;
      }

      // Skip if message was already desensitized (prevent double resolve_model runs)
      const msgStr = String(message);
      if (msgStr.includes("[REDACTED:") || msgStr.startsWith("[SYSTEM]")) {
        api.logger.warn(
          `[GuardClaw] resolve_model: already processed or internal prompt, skipping`,
        );
        return;
      }

      // Pre-read any referenced files BEFORE classification so the model
      // can see actual file content and classify correctly (e.g. delivery info → S2).
      const workspaceDir = api.config.agents?.defaults?.workspace ?? process.cwd();
      let preReadFileContent: string | undefined;
      try {
        preReadFileContent = await tryReadReferencedFile(msgStr, workspaceDir);
        if (preReadFileContent) {
          api.logger.info(
            `[GuardClaw] Pre-read referenced file for classification (${preReadFileContent.length} chars)`,
          );
        } else {
          api.logger.error(`[GuardClaw] resolve_model: Failed to pre-read referenced file.`);
        }
      } catch (fileErr) {
        api.logger.warn(
          `[GuardClaw] Failed to pre-read file for classification: ${String(fileErr)}`,
        );
      }

      api.logger.info(
        `[GuardClaw] resolve_model: calling detectSensitivityLevel with message="${msgStr.slice(0, 80)}"`,
      );

      const result = await detectSensitivityLevel(
        {
          checkpoint: "onUserMessage",
          message,
          sessionKey,
          agentId: ctx.agentId,
          fileContentSnippet: preReadFileContent?.slice(0, 800),
        },
        api.pluginConfig,
        api.logger,
      );

      api.logger.info(
        `[GuardClaw] resolve_model: detection result: level=${result.level}, reason=${result.reason}`,
      );

      recordDetection(sessionKey, result.level, "onUserMessage", result.reason);

      // ── S3: redirect to guard subsession with local-only model ──
      if (result.level === "S3") {
        const guardCfg = getGuardAgentConfig(privacyConfig);
        api.logger.info(`[GuardClaw] S3 detected. Guard config: ${JSON.stringify(guardCfg)}`);
        const guardProvider = guardCfg?.provider ?? "ollama";
        const guardModelName = guardCfg?.modelName ?? "openbmb/minicpm4.1";
        const guardAgentId = guardCfg?.id ?? "guard";

        markSessionAsPrivate(sessionKey, result.level);

        api.logger
          .info(`[GuardClaw] S3 detected. Redirecting to local sub-agent session: provider-name:${guardProvider}
           agent-id:${guardAgentId} model-name:${guardModelName}`);

        // Emit UI event
        api.emitEvent?.("privacy_activated", {
          active: true,
          level: result.level,
          model: `${guardProvider}/${guardModelName}`,
          provider: guardProvider,
          reason: result.reason ?? "S3 content detected",
          sessionKey,
        });

        // Generate a unique session key for this S3 task, ensuring it runs on the guard agent
        const s3SessionKey = `agent:${guardAgentId}:s3-guard-${Date.now()}`;

        // Build a prompt that includes the file content if available
        let taskPrompt = msgStr;
        if (preReadFileContent) {
          taskPrompt += `\n\n--- SENSITIVE FILE CONTENT ---\n${preReadFileContent}\n--- END CONTENT ---\n\nPlease handle the user's request based on this content.`;
        }

        return {
          reason: `GuardClaw: S3 — routing directly to guard sub-agent`,
          sessionKey: s3SessionKey,
          provider: guardProvider,
          model: guardModelName,
          deliverToOriginal: true,
          extraSystemPrompt: getGuardAgentSystemPrompt(),
          userPromptOverride: taskPrompt,
        };
      }

      // ── S2: desensitize content, then forward to cloud model ──
      if (result.level === "S2") {
        markSessionAsPrivate(sessionKey, result.level);

        api.logger.info(`[GuardClaw] S2 detected. Desensitizing content for cloud model.`);

        // Reuse pre-read file content (already fetched before classification)
        const fileContent = preReadFileContent;
        if (fileContent) {
          api.logger.info(
            `[GuardClaw] Using pre-read file for S2 desensitization (${fileContent.length} chars)`,
          );
        }

        let desensitizedPrompt: string;
        let wasModelUsed = false;

        if (fileContent) {
          // File-reference case: desensitize the FILE CONTENT, keep the request intact
          const { desensitized: desensitizedFile, wasModelUsed: fileModelUsed } =
            await desensitizeWithLocalModel(fileContent, privacyConfig);
          wasModelUsed = fileModelUsed;

          // Strip file path from message so cloud model doesn't try to read it again
          const filePathPattern =
            /(?:[\w./-]+\/)?[\w\u4e00-\u9fff._-]+\.(?:xlsx|xls|csv|txt|docx|json|md)/g;
          const taskDescription = message
            .replace(filePathPattern, "")
            .replace(/\s{2,}/g, " ")
            .trim();

          // Detect user language to instruct the cloud model accordingly
          const hasChinese = /[\u4e00-\u9fff]/.test(taskDescription);
          const langInstruction = hasChinese
            ? `请仅根据上方已脱敏的内容完成任务。不要读取任何文件——内容已经提供。\n**重要：回复中不得出现任何 [REDACTED:xxx] 标记。直接省略隐私信息，用自然语言概括即可（例如"您的地址"、"您的电话"等）。请用中文回复。**`
            : `Complete the task based ONLY on the desensitized content above. Do NOT read any files — the content is already provided.\n**IMPORTANT: Your reply must NOT contain any [REDACTED:xxx] tags. Simply omit private details or describe them in natural language (e.g. "your address", "your phone number", "the recipient", etc.). Reply in the same language the user used.**`;

          // Build a prompt: task description (no file path) + desensitized content + clear instructions
          desensitizedPrompt = `${taskDescription}\n\n--- FILE CONTENT ---\n${desensitizedFile}\n--- END FILE CONTENT ---\n\n${langInstruction}`;
          api.logger.info(
            `[GuardClaw] S2 file desensitization complete (model=${wasModelUsed}, ${desensitizedFile.length} chars)`,
          );

          // Track which files were pre-read so we can block tool reads for them
          markPreReadFiles(sessionKey, message);
        } else {
          // Inline PII case: desensitize the user message directly
          const { desensitized, wasModelUsed: msgModelUsed } = await desensitizeWithLocalModel(
            message,
            privacyConfig,
          );
          wasModelUsed = msgModelUsed;
          desensitizedPrompt = desensitized;
          api.logger.info(
            `[GuardClaw] S2 message desensitization complete (model=${wasModelUsed})`,
          );
        }

        // Persist the ORIGINAL message to full history
        const sessionManager = getDefaultSessionManager();
        await sessionManager.persistMessage(sessionKey, {
          role: "user",
          content: message,
          timestamp: Date.now(),
          sessionKey,
        });

        // Emit UI event
        const localModelId = privacyConfig.localModel?.model ?? "openbmb/minicpm4.1";
        const localProvider = privacyConfig.localModel?.provider ?? "ollama";
        api.emitEvent?.("privacy_activated", {
          active: true,
          level: result.level,
          model: `${localProvider}/${localModelId}`,
          provider: localProvider,
          desensitized: true,
          wasModelUsed,
          reason: result.reason ?? "S2 content detected — desensitized",
          sessionKey,
        });

        // Forward the DESENSITIZED content to cloud (don't change provider/model)
        return {
          reason: `GuardClaw: S2 — content desensitized before cloud delivery`,
          userPromptOverride: desensitizedPrompt,
        };
      }

      // ── S1: no intervention ──
      // Session is clean, use cloud model normally
      api.logger.info(`[GuardClaw] resolve_model: S1 detected. Using cloud model as normal.`);
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in resolve_model hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 7: message_sending — Guard subagent announce & outbound messages
  //
  //   When a subagent finishes and announces results back to the requester
  //   chat, this hook scans the outbound content. If the announce reply
  //   leaks S3 data, we cancel it. If S2 PII is found, we redact before
  //   delivery. This is the safety-net: even if the subagent processed
  //   sensitive data, the announce message is scrubbed.
  // =========================================================================
  api.on("message_sending", async (event, _ctx) => {
    try {
      const { content } = event;

      if (!content || !content.trim()) {
        return;
      }

      const privacyConfig = getPrivacyConfigFromApi(api);
      if (!privacyConfig.enabled) {
        return;
      }

      // Run detection on the outbound message content
      const result = await detectSensitivityLevel(
        {
          checkpoint: "onToolCallExecuted", // reuse post-execution checkpoint config
          message: content,
        },
        api.pluginConfig,
        api.logger,
      );

      if (result.level === "S3") {
        api.logger.warn(
          `[GuardClaw] BLOCKED outbound message: S3 content detected in message_sending. ` +
            `Reason: ${result.reason ?? "private data"}`,
        );
        return {
          cancel: true,
        };
      }

      if (result.level === "S2") {
        api.logger.info(
          `[GuardClaw] S2 content in outbound message. Redacting PII before delivery.`,
        );
        const { desensitized } = await desensitizeWithLocalModel(content, privacyConfig);
        return {
          content: desensitized,
        };
      }

      // S1: pass through
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in message_sending hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 8: before_agent_start — Guard subagent session prompts
  //
  //   When any agent run starts (including subagent runs whose session keys
  //   contain ":subagent:"), we scan the initial prompt for sensitive content.
  //   This catches cases where a parent agent embeds private data into the
  //   subagent's task description or bootstrap context.
  //
  //   S3 → inject a system prompt warning the subagent to refuse and explain
  //   S2 → inject a system prompt instructing the subagent to redact PII
  // =========================================================================
  api.on("before_agent_start", async (event, ctx) => {
    try {
      const { prompt } = event;
      const sessionKey = ctx.sessionKey ?? "";

      // Only apply to subagent sessions (session key contains ":subagent:")
      if (!sessionKey.includes(":subagent:")) {
        return;
      }

      if (!prompt || !prompt.trim()) {
        return;
      }

      const privacyConfig = getPrivacyConfigFromApi(api);
      if (!privacyConfig.enabled) {
        return;
      }

      const result = await detectSensitivityLevel(
        {
          checkpoint: "onUserMessage",
          message: prompt,
          sessionKey,
          agentId: ctx.agentId,
        },
        api.pluginConfig,
        api.logger,
      );

      if (result.level === "S3") {
        // If the subagent is safe local, inject guard prompts instead of blocking
        const modelStr = String((ctx as any).model ?? "");
        const providerStr = String((ctx as any).provider ?? "");
        const isSafeLocal =
          isLocalProvider(providerStr) ||
          modelStr.includes("ollama/") ||
          modelStr.includes("llama");

        if (isSafeLocal) {
          api.logger.info(
            `[GuardClaw] Subagent session ${sessionKey} prompt contains S3 content, but provider is safe local. Injecting guard system prompt.`,
          );
          return {
            systemPrompt: getGuardAgentSystemPrompt(),
          };
        }

        api.logger.warn(
          `[GuardClaw] Subagent session ${sessionKey} prompt contains S3 content! ` +
            `Injecting privacy guard instructions. Reason: ${result.reason ?? "private data"}`,
        );

        // Inject a system prompt that tells the subagent to refuse processing
        // and explain that the task contains private data
        return {
          systemPrompt:
            `[PRIVACY GUARD] This task contains S3-level PRIVATE content (${result.reason ?? "sensitive data detected"}). ` +
            `You MUST NOT process, analyze, or echo any of this data. ` +
            `Reply with: "This task contains private data that cannot be processed by a cloud model. ` +
            `Please handle it directly in the main session where local-model privacy guard is available." ` +
            `Do NOT attempt the task.`,
        };
      }

      if (result.level === "S2") {
        api.logger.info(
          `[GuardClaw] Subagent session ${sessionKey} prompt contains S2 content. ` +
            `Injecting PII handling instructions.`,
        );

        return {
          prependContext:
            `[PRIVACY NOTICE] The task below may contain personally identifiable information (PII). ` +
            `When producing output, do NOT echo exact PII values (addresses, phone numbers, emails, names). ` +
            `Use generic references instead (e.g. "the recipient's address", "the phone number on file"). ` +
            `Never include raw PII in your final response.`,
        };
      }

      // S1: no intervention
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_agent_start hook: ${String(err)}`);
    }
  });

  api.logger.info(
    "[GuardClaw] All hooks registered successfully (8 hooks: message, tool, result, persist, session, model, outbound, subagent)",
  );
}

// ==========================================================================
// Helpers
// ==========================================================================

/**
 * Merge user config with defaults and return typed PrivacyConfig
 */
function getPrivacyConfigFromApi(api: OpenClawPluginApi): PrivacyConfig {
  return mergeWithDefaults(
    (api.pluginConfig?.privacy as PrivacyConfig) ?? {},
    defaultPrivacyConfig,
  );
}

function mergeWithDefaults(
  userConfig: PrivacyConfig,
  defaults: typeof defaultPrivacyConfig,
): PrivacyConfig {
  return {
    enabled: userConfig.enabled ?? defaults.enabled,
    checkpoints: {
      onUserMessage: userConfig.checkpoints?.onUserMessage ?? defaults.checkpoints?.onUserMessage,
      onToolCallProposed:
        userConfig.checkpoints?.onToolCallProposed ?? defaults.checkpoints?.onToolCallProposed,
      onToolCallExecuted:
        userConfig.checkpoints?.onToolCallExecuted ?? defaults.checkpoints?.onToolCallExecuted,
    },
    rules: {
      keywords: {
        S2: userConfig.rules?.keywords?.S2 ?? defaults.rules?.keywords?.S2,
        S3: userConfig.rules?.keywords?.S3 ?? defaults.rules?.keywords?.S3,
      },
      patterns: {
        S2: userConfig.rules?.patterns?.S2 ?? defaults.rules?.patterns?.S2,
        S3: userConfig.rules?.patterns?.S3 ?? defaults.rules?.patterns?.S3,
      },
      tools: {
        S2: {
          tools: userConfig.rules?.tools?.S2?.tools ?? defaults.rules?.tools?.S2?.tools,
          paths: userConfig.rules?.tools?.S2?.paths ?? defaults.rules?.tools?.S2?.paths,
        },
        S3: {
          tools: userConfig.rules?.tools?.S3?.tools ?? defaults.rules?.tools?.S3?.tools,
          paths: userConfig.rules?.tools?.S3?.paths ?? defaults.rules?.tools?.S3?.paths,
        },
      },
    },
    localModel: {
      enabled: userConfig.localModel?.enabled ?? defaults.localModel?.enabled,
      provider: userConfig.localModel?.provider ?? defaults.localModel?.provider,
      model: userConfig.localModel?.model ?? defaults.localModel?.model,
      endpoint: userConfig.localModel?.endpoint ?? defaults.localModel?.endpoint,
    },
    guardAgent: {
      id: userConfig.guardAgent?.id ?? defaults.guardAgent?.id,
      workspace: userConfig.guardAgent?.workspace ?? defaults.guardAgent?.workspace,
      model: userConfig.guardAgent?.model ?? defaults.guardAgent?.model,
    },
    session: {
      isolateGuardHistory:
        userConfig.session?.isolateGuardHistory ?? defaults.session?.isolateGuardHistory,
      baseDir: userConfig.session?.baseDir ?? defaults.session?.baseDir,
    },
    debug: {
      interceptLlmRequests:
        userConfig.debug?.interceptLlmRequests ?? defaults.debug?.interceptLlmRequests,
    },
  };
}

/**
 * Extract text from message object
 */
function extractMessageText(message: unknown): string | undefined {
  if (typeof message === "string") {
    return message;
  }

  if (message && typeof message === "object") {
    const msg = message as Record<string, unknown>;
    if (typeof msg.text === "string") return msg.text;
    if (typeof msg.content === "string") return msg.content;
    if (typeof msg.body === "string") return msg.body;
  }

  return undefined;
}

/**
 * Build a wrapped user prompt for the guard agent (S3)
 */
function buildGuardUserPrompt(
  originalMessage: string,
  level: string,
  reason?: string,
  fileContent?: string,
): string {
  let prompt = `[Privacy Level: ${level}${reason ? ` — ${reason}` : ""}]

${originalMessage}`;

  if (fileContent) {
    prompt += `\n\n--- FILE CONTENT (read locally, never sent to cloud) ---\n${fileContent}\n--- END FILE CONTENT ---`;
  }

  return prompt;
}

/**
 * Try to read a file referenced in the user message.
 * Supports text files directly and xlsx/docx via conversion.
 */
async function tryReadReferencedFile(
  message: string,
  workspaceDir: string,
): Promise<string | undefined> {
  // Extract file paths from the message (e.g. test-files/foo.xlsx, /path/to/file.txt)
  const filePattern =
    /(?:^|\s)((?:[\w./-]+\/)?[\w\u4e00-\u9fff._-]+\.(?:xlsx|xls|csv|txt|docx|json|md))\b/g;
  const matches: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = filePattern.exec(message)) !== null) {
    matches.push(m[1]);
  }

  if (matches.length === 0) return undefined;

  // Try multiple base directories — workspace first, cwd, then parent of cwd as fallback
  const cwd = process.cwd();
  const baseDirs = [
    workspaceDir,
    cwd,
    resolve(cwd, ".."), // parent dir (gateway may run from openclaw/ subdir)
  ].filter(Boolean);

  for (const filePath of matches) {
    try {
      let absPath = "";
      for (const base of baseDirs) {
        const candidate = resolve(base, filePath);
        if (existsSync(candidate)) {
          absPath = candidate;
          break;
        }
      }
      // Also try the file path as-is (if absolute)
      if (!absPath && existsSync(filePath)) absPath = resolve(filePath);
      if (!absPath) continue;

      const ext = filePath.split(".").pop()?.toLowerCase();

      if (ext === "xlsx" || ext === "xls") {
        // Convert xlsx → csv via xlsx2csv or python
        try {
          const csv = execSync(`xlsx2csv "${absPath}"`, {
            encoding: "utf-8",
            timeout: 10000,
          });
          return `[Converted from ${filePath}]\n${csv}`;
        } catch {
          try {
            const csv = execSync(
              `python3 -c "import openpyxl; wb=openpyxl.load_workbook('${absPath}'); ws=wb.active; [print(','.join(str(c.value or '') for c in row)) for row in ws.iter_rows()]"`,
              { encoding: "utf-8", timeout: 10000 },
            );
            return `[Converted from ${filePath}]\n${csv}`;
          } catch {
            return undefined;
          }
        }
      } else if (ext === "docx") {
        // Try to extract text from docx — try multiple python paths
        const pyCmd = `"from docx import Document; d=Document('${absPath}'); print('\\n'.join(p.text for p in d.paragraphs))"`;
        for (const py of ["python3", `${process.env.HOME}/miniconda3/bin/python3`]) {
          try {
            const text = execSync(`${py} -c ${pyCmd}`, { encoding: "utf-8", timeout: 10000 });
            return `[Extracted from ${filePath}]\n${text}`;
          } catch {
            continue;
          }
        }
        return undefined;
      } else {
        // Text file — read directly
        const content = await readFile(absPath, "utf-8");
        return `[Content of ${filePath}]\n${content.slice(0, 10000)}`;
      }
    } catch {
      // Skip files we can't read
      continue;
    }
  }

  return undefined;
}

/**
 * Extract path-like values from tool params for file-access guarding
 */
function extractPathValuesFromParams(params: Record<string, unknown>): string[] {
  const paths: string[] = [];
  const pathKeys = ["path", "file", "filepath", "filename", "dir", "directory", "target", "source"];

  for (const key of pathKeys) {
    const value = params[key];
    if (typeof value === "string" && value.trim()) {
      paths.push(value.trim());
    }
  }

  // Recurse into nested objects
  for (const value of Object.values(params)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      paths.push(...extractPathValuesFromParams(value as Record<string, unknown>));
    }
  }

  return paths;
}
