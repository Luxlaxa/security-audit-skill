#!/usr/bin/env node

/**
 * Security Audit Pre-Push Gate Hook
 *
 * Claude Code PreToolUse hook that triggers a security gate check
 * when a `git push` command is detected.
 *
 * Install in settings.json:
 * {
 *   "hooks": {
 *     "PreToolUse": [{
 *       "matcher": "Bash",
 *       "hooks": [{
 *         "type": "command",
 *         "command": "node ~/.claude/skills/security-audit/hooks/pre-push-gate.js"
 *       }]
 *     }]
 *   }
 * }
 */

// Read tool input from stdin
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  try {
    const toolInput = JSON.parse(input);
    const command = toolInput.tool_input?.command || '';

    // Only intercept git push commands
    if (!command.match(/\bgit\s+push\b/)) {
      process.exit(0);
    }

    // Signal to Claude Code to run security gate
    const message = [
      '🔒 SECURITY GATE: Pre-push check triggered.',
      '',
      'Before pushing, run a security gate check using the security-audit skill:',
      '  /security-audit --gate',
      '',
      'This checks for Critical and High severity issues.',
      'Critical findings will block the push.',
      '',
      'To skip this check (not recommended): push with --no-verify'
    ].join('\n');

    console.log(message);
    process.exit(0);
  } catch (err) {
    // On parse error, don't block — fail open
    process.exit(0);
  }
});
