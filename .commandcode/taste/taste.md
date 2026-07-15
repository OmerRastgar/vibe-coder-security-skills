# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# skill-structure
- For vulnerability/security scanning skills: include executable scripts (Python, Bash, or PowerShell) alongside SKILL.md to automate scanning and credential detection. Confidence: 0.70
- Structure skills as a dedicated folder containing SKILL.md (with YAML frontmatter + instructions) plus supporting executable scripts, so the skill is immediately usable as a drop-in. Confidence: 0.70

# architecture
- Split vulnerability scanning into two separate Docker containers: a DAST container (Nuclei-based, scans live URLs on port 5000) and a SAST container (Semgrep/TruffleHog/Checkov-based, scans source code directories on port 5001). Confidence: 0.70

# git
- When setting up a GitHub repo, first push the basic project structure, then commit each vulnerability/feature individually with proper descriptive commits, and remove temporary/output files before committing. Confidence: 0.70

