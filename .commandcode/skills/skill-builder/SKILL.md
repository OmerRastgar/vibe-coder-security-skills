---
name: skill-builder
description: Scaffold and build new Command Code agent skills. Use when the user wants to create, add, or generate a skill, or when a task should become a reusable skill. Produces a correctly formatted SKILL.md (YAML frontmatter + instruction body) under .commandcode/skills/<name>/ and can bootstrap follow-up files like templates or reference docs.
---

# Skill Builder

You create new Command Code agent skills. A skill is a knowledge module that teaches the agent how to perform a specialized, repeatable task. Skills live at `.commandcode/skills/<skill-name>/SKILL.md`.

## Skill file format

Every skill requires a `SKILL.md` with YAML frontmatter followed by a Markdown instruction body.

```markdown
---
name: <skill-id>
description: <one or two sentences describing WHEN to use this skill, with concrete trigger keywords>
---

# <Human Title>

<Clear, step-by-step instructions the agent follows when this skill is active.
 Include the workflow, decision points, file locations, and any constraints.>
```

Frontmatter rules:
- `name`: lowercase, hyphenated identifier (e.g., `security-audit`). No spaces.
- `description`: MANDATORY. Describe the task AND the trigger conditions. Include keywords that match when the user would want this skill. This is how the agent decides to load the skill, so be specific about use cases.

Body rules:
- Write directly to the agent (second person: "You will...", "Read the file...").
- Be concrete: name real files, commands, and decision points.
- Keep it focused — a skill should encode a clear procedure, not a novel.

## Workflow

When asked to build a skill:

1. **Clarify scope (only if ambiguous).** If the user gave a clear name + purpose, proceed. Otherwise ask: what should the skill do, when should it trigger, and does it need helper files (templates, scripts, reference docs)?
2. **Choose a name.** Derive a lowercase hyphenated `name` from the purpose.
3. **Create the folder** `.commandcode/skills/<name>/`.
4. **Write `SKILL.md`** with frontmatter + body following the format above.
5. **Add helper files if needed** (e.g., `template.md`, `scripts/`, reference data). Reference them from the SKILL.md body with relative paths. Keep skills self-contained in their folder.
6. **Validate** the result: confirm frontmatter is valid YAML, `name` matches the folder, and `description` is present.

## Naming & placement

- Project skills: `.commandcode/skills/<name>/SKILL.md` (this repo).
- The folder name and the frontmatter `name` MUST match exactly.

## Example: minimal skill

`.commandcode/skills/hello-world/SKILL.md`:
```markdown
---
name: hello-world
description: Prints a friendly greeting. Use when the user asks to say hello or test the skill system.
---

# Hello World

Respond with a short, friendly greeting to the user.
```

## Guardrails

- Never edit or write files inside `node_modules`, global command-code install, or other skills' folders unless explicitly asked.
- Do not invent URLs. Reference only files you create or that already exist in the workspace.
- Keep each skill single-purpose. If a request spans clearly separate concerns, propose multiple skills.
