# Vibe Coder Guide to Security

This guide is designed specifically for **vibe coders,** developers who build quickly with AI assistants. You don't need to be a security expert or fully understand every vulnerability to build secure software.

Instead, this guide helps you use the same AI tools that generated your code to **identify, verify, and fix security issues** before they become real problems.

For every security vulnerability, you will find:

- A brief explanation of what the vulnerability is and why it matters.
- A standalone Mermaid flowchart that visually maps where the vulnerability typically exists within an application's architecture, including the affected components, files, services, and code paths. These diagrams are designed to show you **where to look**, since AI-generated code and automated reviews often miss the broader architectural context.
- A ready-to-use prompt that you can simply copy and paste into your preferred LLM or AI coding assistant. The prompt instructs the AI to inspect your project for that specific vulnerability, identify the affected files and code, explain its findings.

## Index

| # | Folder | Vulnerability | Primary Targets |
|---|--------|---------------|-----------------|
