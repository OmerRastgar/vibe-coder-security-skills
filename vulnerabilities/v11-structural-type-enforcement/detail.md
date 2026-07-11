# V11 — Structural Type Enforcement

Risks of loose type enforcement and mass assignment when mapping user input to internal data structures. Dangerous practices include using spread operators in JavaScript/TypeScript, bypassing validation with `as any`, unpacking raw JSON dictionaries directly into ORMs in Python, and utilizing overly permissive DTOs or blind automappers in compiled languages.

Targets: JS/TS (Node.js), Python (FastAPI/Django), reflection / low-level bypasses.
