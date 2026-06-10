# How To Make A CLI For Your Corp

A practical guide to building an internal CLI tool that your teammates actually want to use.

This repo documents the real-world patterns we learned building `ks-cli` — a command-line interface for Kuaishou's internal developer platforms. It covers SSO authentication, plugin architecture, command discovery, skill distribution, and everything in between.

## Why This Exists

Most internal tools start as a web dashboard. Then someone wants to automate a workflow, so they write a Python script. Then another team copies it and changes two lines. Six months later you have 47 semi-broken scripts scattered across Slack, Confluence, and private Gists.

A well-designed CLI fixes this by:

- **Giving every team a single entry point** — one binary, consistent flags, predictable behavior
- **Embedding auth into the tool** — SSO login happens once, then every command "just works"
- **Making automation trivial** — pipe it, script it, cron it, CI it
- **Distributing via the tools developers already use** — npm, Homebrew, or a simple `curl | bash`

## Table of Contents

1. [SSO Authentication — The "It Just Works" Login Flow](./chapters/01-sso-auth.md)
2. [Capture & Replay — Reverse-Engineering APIs from Browser Interactions](./chapters/02-capture-and-replay.md)
3. *(WIP) Command Discovery & Manifests*
4. *(WIP) HTTP vs Script Commands*
5. *(WIP) Plugin / Skill Architecture*
6. *(WIP) Distribution & Auto-Update*

## Who This Is For

- You maintain internal developer tools and want to reduce support burden
- You're tired of writing one-off scripts that break every time the auth flow changes
- You want your CLI to feel as polished as `gh`, `vercel`, or `flyctl`

## Tech Stack

The examples are in **TypeScript / Node.js**, but the patterns apply to any language. We use:

- [Commander.js](https://github.com/tj/commander.js) for CLI argument parsing
- [Playwright](https://playwright.dev) for browser-based SSO login
- Plain `fetch` for HTTP commands
- `child_process.spawn` for script commands

---

Licensed under MIT.
