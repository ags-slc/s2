import type { Plugin } from "@opencode-ai/plugin"

// s2 OpenCode plugin — wraps commands with s2 exec for secret injection.
// Requires: s2 in PATH.
// Install: copy to ~/.config/opencode/plugins/s2.ts

export const S2Plugin: Plugin = async ({ $ }) => {
  try {
    await $`which s2`.quiet()
  } catch {
    console.warn("[s2] s2 binary not found in PATH — plugin disabled")
    return {}
  }

  return {
    "tool.execute.before": async (input, output) => {
      const tool = String(input?.tool ?? "").toLowerCase()
      if (tool !== "bash" && tool !== "shell") return
      const args = output?.args
      if (!args || typeof args !== "object") return

      const command = (args as Record<string, unknown>).command
      if (typeof command !== "string" || !command) return

      // Skip s2 commands to prevent infinite loops
      if (command.trimStart().startsWith("s2 ") || command.includes("s2 exec")) return

      try {
        const json = JSON.stringify({ tool_input: { command } })
        const result = await $`echo ${json} | s2 hook --format cursor`.quiet().nothrow()
        const parsed = JSON.parse(String(result.stdout).trim())
        if (parsed?.updated_input?.command) {
          ;(args as Record<string, unknown>).command = parsed.updated_input.command
        }
      } catch {
        // s2 hook failed — pass through unchanged
      }
    },
  }
}
