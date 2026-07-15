# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# skill-structure
- For vulnerability/security scanning skills: include executable scripts (Python, Bash, or PowerShell) alongside SKILL.md to automate scanning and credential detection. Confidence: 0.70
- Structure skills as a dedicated folder containing SKILL.md (with YAML frontmatter + instructions) plus supporting executable scripts, so the skill is immediately usable as a drop-in. Confidence: 0.70

# architecture
- Split vulnerability scanning into two separate Docker containers: a DAST container (Nuclei-based, scans live URLs on port 5000) and a SAST container (Semgrep/TruffleHog/Checkov-based, scans source code directories on port 5001). Confidence: 0.70

# docker
- For COPY commands with paths containing spaces (e.g., "Nuclei Templates/"), use JSON array form: COPY ["src dir/", "/dest/"] instead of COPY "src dir/" /dest/ to avoid Docker's shell-parsing errors on Windows. Confidence: 0.70

# api-design
- Save scan results to persistent external storage (file/database) in addition to returning them in the API response, so users can inspect raw output verbosity and debug failures offline. Confidence: 0.70

# git
- When setting up a GitHub repo, first push the basic project structure, then commit each vulnerability/feature individually with proper descriptive commits, and remove temporary/output files before committing. Confidence: 0.70

# naming
- Use descriptive, purpose-indicating names for directories: prefer "Semgrep Rules" over "sast" so the folder name tells you what it contains at a glance. Confidence: 0.65
- Capitalize top-level directory names (e.g., "Vulnerabilities" not "vulnerabilities", "Nuclei Templates" not "nuclei templates"). Confidence: 0.60

# instructions-style
- Prefer UI/console-based instructions (Google Cloud Console, web interfaces) over CLI/gcloud commands when providing deployment or configuration guidance. Confidence: 0.70

