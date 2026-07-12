---
name: v3-client-side-misplacement
description: Audit a codebase for Client-Side Security Misplacements (V3). Use when the user wants to check for frontend trust issues, client-side authorization bypasses, route guard vulnerabilities, unverified JWT claims, client-driven pricing logic, or any security logic that should be enforced on the backend but is only enforced in the browser.
---

# V3 — Client-Side Security Misplacement Audit

You audit a target codebase for Client-Side Security Misplacements using the vulnerability definition and audit prompt from `vulnerabilities/v3-client-side-misplacement/`.

## Workflow

1. **Orient with the flowchart.** Read `vulnerabilities/v3-client-side-misplacement/flowchart.md` to understand the three attack surfaces to focus on:
   - Auth & Access (route guards, conditional UI, feature flags, local session, unverified JWT)
   - Forms & Inputs (form fields, input spinners, dropdowns, file inputs, search bars)
   - Data Flow & Math (API payloads, UI data masking, checkout/pricing math, local game state)

2. **Identify target files.** Scan the codebase for frontend and client-adjacent artifacts:
   - SPA source files (React, Vue, Angular, Svelte, Next.js components)
   - Routing config files (e.g., `router/index.ts`, `App.tsx`, route guard middleware)
   - Form validation and input components
   - State management files (Redux, Pinia, Zustand, Vuex stores)
   - Feature flag implementations
   - Checkout, pricing, or cart logic
   - Any file that reads from `localStorage`, `sessionStorage`, or decodes a JWT client-side

3. **Run the audit.** Feed the identified code into the audit prompt from `vulnerabilities/v3-client-side-misplacement/prompt.md` as the INPUT section. Apply these specific checks:
   - **Route guards:** Is access control enforced only in the router, with no corresponding backend authorization check?
   - **Conditional rendering:** Does hiding UI elements (via `v-if`, `&&`, ternary) substitute for actual access control?
   - **Feature flags:** Are paid/premium features only hidden client-side with no server enforcement?
   - **JWT / session:** Is a user's role or privilege read directly from a decoded JWT or localStorage without backend signature verification?
   - **Pricing/math:** Are totals, discounts, or quantities calculated in the browser and submitted to the API without server-side recalculation?
   - **Input limits:** Are min/max constraints only applied via UI controls (e.g., `<input max="100">`) with no backend bounds check?
   - **Data masking:** Is sensitive data sent to the client and hidden in the UI, rather than excluded from the API response entirely?

4. **Report findings** using the output format defined in `vulnerabilities/v3-client-side-misplacement/prompt.md`:
   - Summary: total vulnerability count + high-risk components identified
   - Per finding: file/location, vulnerability category, target area, and exact code evidence

5. **Suggest fixes.** For each finding, recommend the backend enforcement that should mirror or replace the client-side check. Examples:
   - Route guard bypass → add server-side middleware/policy check on the protected API route
   - Client JWT role check → verify the token signature and claims server-side on every protected request
   - Client-side pricing → recalculate totals server-side before processing payment
   - UI-only input limits → add schema validation (Zod, Pydantic, Joi) on the backend handler

## Guardrails

- Flag frontend validation as a vulnerability only when there is **no evidence** of a redundant backend enforcement layer. If both exist, note it as good practice.
- Do not flag pure UX validation (e.g., showing an error message before form submit) as a security issue unless it is the sole gating mechanism.
- Reference only files and code that exist in the provided input. Do not hallucinate vulnerabilities.
- Keep findings actionable — pair every finding with a concrete remediation step.
