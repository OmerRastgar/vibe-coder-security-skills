# Vibe Coder Guide to Security

This guide is designed specifically for **vibe coders,** developers who build quickly with AI assistants. You don't need to be a security expert or fully understand every vulnerability to build secure software.

Instead, this guide helps you use the same AI tools that generated your code to **identify, verify, and fix security issues** before they become real problems.

For every security vulnerability, you will find:

- A brief explanation of what the vulnerability is and why it matters.
- A standalone Mermaid flowchart that visually maps where the vulnerability typically exists within an application's architecture, including the affected components, files, services, and code paths. These diagrams are designed to show you **where to look**, since AI-generated code and automated reviews often miss the broader architectural context.
- A ready-to-use prompt that you can simply copy and paste into your preferred LLM or AI coding assistant. The prompt instructs the AI to inspect your project for that specific vulnerability, identify the affected files and code, explain its findings.

## Vulnerability 1: AI Commit Trap

**Detail:** This vulnerability focuses on the risk of AI assistants and developers inadvertently leaking sensitive secrets into version control systems (like GitHub or GitLab) and container registries (like Docker Hub). It illustrates the pathway from exposed configurations, `.env` files, and Terraform manifests to compromised API keys, AWS credentials, and Kubeconfigs.

```mermaid
flowchart TD
    Root("fa:fa-robot <b>AI Commit Trap</b>")
    Secrets("fa:fa-key Leaked Secrets")
    ScanGH("fa:fa-github Scan Git")
    ScanCR("fa:fa-docker Scan Registry")
    Git("Git History")
    DockerHub("Docker Hub")
    Gitcontainer("GHCR / Quay / GitLab")

    LookFor{"fa:fa-search Targets"}

    Config["Configs"]
    Env[".env"]
    Terraform["Terraform"]
    GitHist["Git Logs"]
    DockerComp["Compose YML"]
    Deps["Manifests"]
    WebConfig["Web Configs"]
    Certs["Crypto Keys"]
    AWS["AWS Creeds"]
    Kube["Kubeconfig"]
    Npm[".npmrc"]

    %% Connections
    Root --> Secrets
    Secrets --> ScanGH & ScanCR
    ScanGH --> Git
    ScanCR --> DockerHub & Gitcontainer

    Git --> LookFor
    DockerHub --> LookFor
    Gitcontainer --> LookFor

    LookFor --> Config & Certs & AWS & Kube & Npm
    Config --> Env & Terraform & GitHist & DockerComp & Deps & WebConfig

    %% Styling
    style Root color:#FFFFFF, fill:#D32F2F, stroke:#9A0007
    style Secrets color:#FFFFFF, fill:#F57C00, stroke:#BB4D00
    style LookFor color:#FFFFFF, fill:#1976D2, stroke:#004BA0
    style Env color:#000000, fill:#E0E0E0, stroke:#B0B0B0
    style AWS color:#000000, fill:#E0E0E0, stroke:#B0B0B0
    style Kube color:#000000, fill:#E0E0E0, stroke:#B0B0B0
```

### Prompt to do an Audit

```
### ROLE
You are an expert DevSecOps Engineer and Static Application Security Testing (SAST) automated agent specializing in secret detection, credential hygiene, and secure software supply chains. Your core directive is to identify the "AI Commit Trap"—the accidental leakage of cryptographic keys, API credentials, configuration files, or environment manifests into version control histories or container registries.

### INPUT
You have been provided with codebase artifacts, which may include:
1. Active configuration files (.env, Terraform manifests, application.yml, web.config, docker-compose.yml).
2. Codebase dependency manifests (.npmrc, pip.conf, cargo/config).
3. Git commit history/logs or file diffs.
4. Dockerfile layers or registry configuration snippets.

### CONTEXT
Modern development workflows, particularly those accelerated by AI coding assistants, frequently suffer from "AI Commit Traps." This happens when automated tools or moving developers unintentionally commit staging environment variables, raw authentication strings, or local infrastructure blueprints into Git histories or containerized layers (e.g., Docker Hub, GHCR). Once these secrets are in the history, they remain exposed even if deleted in a subsequent commit.

### CONSTRAINTS
- **No False Negatives on High-Risk Assets:** You must flag any high-entropy string, explicit variable assignment containing credential keywords (e.g., `AWS_SECRET_ACCESS_KEY`, `PASSWORD`, `PRIVATE_KEY`), or un-ignored sensitive filenames.
- **Strictly Analyze History:** If Git diffs or logs are provided, evaluate the deleted/modified lines to ensure secrets are not buried in older commits.
- **Zero Hallucination:** Only flag secrets or configurations that are explicitly present in the provided input text. Do not assume infrastructure patterns that are not visible.
- **Context-Aware Evaluation:** Distinguish between dummy/placeholder variables (e.g., `db_password=123456`) and potentially live, high-entropy production secrets.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🚨 Secret Detection Summary
* **Total High-Risk Exposures Found:** [Count]
* **Files Affected:** [List of filenames/paths]

---

## 🔍 Detailed Vulnerability Findings

### [Finding #] - [Secret Type / Description]
- **File/Location:** `path/to/file` (or Commit Hash if analyzing history)
- **Exposure Type:** [e.g., .env exposure, Terraform manifest credential, Hardcoded API Key]
- **Evidence:** ```[language]
  [Insert the exact matching line/snippet here, masking the actual secret value for safety, e.g., AIzaSy...xxxx]
```

## Vulnerability 2: Package Hallucination

**Detail:** This vulnerability addresses a unique AI-era vulnerability where Large Language Models "hallucinate" non-existent software packages. Malicious actors scan for these common hallucinations and squat on those names in package registries. If a developer uses the AI's hallucinated code, their manifests and lockfiles pull down malicious payloads.

```mermaid
flowchart TD
    Root2("fa:fa-robot <b>Hallucinations</b>")
    MaliciousPkg("fa:fa-skull-crossbones Squatted Packages")
    ScanEcosystem("fa:fa-shield-halved Scan Dependencies")

    Manifests["Manifests"]
    Lockfiles["Lockfiles"]
    Infra["CI/CD & Infra"]
    CodeFiles["Source Code"]

    LookForPkg{"fa:fa-search Targets"}

    ReqTxt["requirements / pyproject"]
    PkgJson["package.json"]
    GoMod["go.mod"]
    LockJson["package-lock / yarn.lock"]
    PoetryLock["poetry / pipfile.lock"]
    DFile["Dockerfile"]
    Workflows["Workflows YML"]
    Scripts["Setup Scripts"]
    SourceImp["Code Imports"]

    %% Connections
    Root2 --> MaliciousPkg
    MaliciousPkg --> ScanEcosystem
    ScanEcosystem --> Manifests & Lockfiles & Infra & CodeFiles

    Manifests --> LookForPkg
    Lockfiles --> LookForPkg
    Infra --> LookForPkg
    CodeFiles --> LookForPkg

    LookForPkg --> ReqTxt & PkgJson & GoMod & LockJson & PoetryLock & DFile & Workflows & Scripts & SourceImp

    %% Styling
    style Root2 color:#FFFFFF, fill:#7B1FA2, stroke:#4A148C
    style MaliciousPkg color:#FFFFFF, fill:#C2185B, stroke:#880E4F
    style LookForPkg color:#FFFFFF, fill:#00796B, stroke:#004D40
    style ReqTxt color:#000000, fill:#EDE7F6, stroke:#D1C4E9
    style PkgJson color:#000000, fill:#EDE7F6, stroke:#D1C4E9
    style LockJson color:#000000, fill:#E0F2F1, stroke:#B2DFDB
    style DFile color:#000000, fill:#EFFFDE, stroke:#C5E1A5
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Software Supply Chain Security Engineer and Automated Dependency Auditor. Your primary objective is to inspect software projects for AI-generated package hallucinations, typosquatted dependencies, and malicious packages that may have been introduced via AI coding assistants or unverified source code imports.

### INPUT
You have been provided with codebase artifacts, which may include:
1. Dependency Manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`).
2. Lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`).
3. Infrastructure & Automation Files (`Dockerfile`, CI/CD workflow `.yml` files, installation setup scripts).
4. Source Code Files (`.py`, `.js`, `.ts`, `.go`, etc.) containing import/require statements.

### CONTEXT
In the era of AI-assisted development, LLMs frequently "hallucinate" plausible-sounding but non-existent software libraries. Attackers aggressively monitor or predict these common AI hallucinations and register ("squat" on) those exact names in public package registries (npm, PyPI, Crates.io, RubyGems). If a developer accepts the AI's suggestion without verifying it, their manifests pull down malicious payloads during the build process, compromising the CI/CD pipeline or local environments.

### CONSTRAINTS
- **Cross-Reference Manifests vs. Imports:** Correlate listed dependencies in manifests with actual `import`/`require` statements in the source code to find hidden or unlisted packages.
- **Flag Anomalous naming:** Look for high-risk naming conventions often associated with typosquatting or fake packages (e.g., swapping dashes for underscores, common misspells of massive libraries like `boto3`, `requests`, `react`).
- **No External Network Access (Simulated Baseline):** Since you cannot query live registries in real-time, flag packages that match known patterns of common AI hallucinations (e.g., highly descriptive, generic names like `python-string-utils` or `react-native-simple-auth-handler`) or libraries that look out of place given the project scope.
- **Maintain a Low False Positive Rate:** Distinguish between legitimate, obscure internal/enterprise private packages (often scoped like `@company/package`) and potentially malicious public packages.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## ⚠️ Supply Chain & Package Analysis Summary
* **Total Suspicious Packages Identified:** [Count]
* **Files / Manifests Affected:** [List files, e.g., package.json, main.py]

---

## 🕵️‍♂️ Detailed Dependency Findings

### [Finding #] - Potential [Hallucinated / Typosquatted] Package
- **Package Name:** `[Name of the suspicious package]`
- **Registry Ecosystem:** [e.g., npm, PyPI, Go Modules, RubyGems]
- **Location Found:** Found in `path/to/file` at line [X] (or inside import block of `filename`)
- **Risk Assessment:** [Explain why this looks like an AI hallucination or typosquatting attempt. E.g., "The package name mimics 'X' but changes syntax," or "The package uses a highly generic AI-fictionalized naming pattern."]
- **Remediation Action:** 1. Verify if this package actually exists and is maintained on the official registry.
  2. If it is a hallucination, remove it from the manifest and replace it with the intended, legitimate library (e.g., specify the correct package name).
  3. Clean local package caches (`npm cache clean`, `pip cache purge`) to ensure no malicious payloads were stored.
```

## Vulnerability 3: Client-Side Security Misplacements

**Detail:** Focuses on applications that misplace their trust in frontend client logic rather than backend enforcement. It maps out vulnerabilities where route guards, feature flags, checkout math, or unverified JWT claims can be bypassed directly by manipulating the browser environment.

```mermaid
flowchart TD
    Root3("fa:fa-laptop-code <b>Client Misplacements</b>")
    ClientTrust("fa:fa-triangle-exaggeration Frontend Trust")
    ScanClient("fa:fa-magnifying-glass-shield Audit UI Logic")

    Navigation["Auth & Access"]
    InputValidation["Forms & Inputs"]
    PayloadData["Data Flow & Math"]

    LookForClient{"fa:fa-search Targets"}

    RouteGuards["Route Guards"]
    CondRender["Conditional UI"]
    FeatureFlags["Feature Flags"]
    SessionVerify["Local Session"]
    JWTClaims["Unverified JWT"]

    FormFields["Form Fields"]
    NumSpinners["Input Spinners"]
    Dropdowns["UI Dropdowns"]
    ClientFileUploads["File Inputs"]
    SearchBars["Search Bars"]

    APIPayloads["API Payloads"]
    DataMasking["UI Data Masking"]
    CheckoutMath["Pricing Math"]
    GamingState["Local Game State"]

    %% Connections
    Root3 --> ClientTrust
    ClientTrust --> ScanClient
    ScanClient --> Navigation & InputValidation & PayloadData

    Navigation --> LookForClient
    InputValidation --> LookForClient
    PayloadData --> LookForClient

    LookForClient --> RouteGuards & CondRender & FeatureFlags & SessionVerify & JWTClaims
    LookForClient --> FormFields & NumSpinners & Dropdowns & ClientFileUploads & SearchBars
    LookForClient --> APIPayloads & DataMasking & CheckoutMath & GamingState

    %% Styling
    style Root3 color:#FFFFFF, fill:#0288D1, stroke:#01579B
    style ClientTrust color:#FFFFFF, fill:#E64A19, stroke:#BF360C
    style LookForClient color:#FFFFFF, fill:#388E3C, stroke:#1B5E20
    style RouteGuards color:#000000, fill:#E1F5FE, stroke:#B3E5FC
    style FormFields color:#000000, fill:#F1F8E9, stroke:#DCEDC8
    style APIPayloads color:#000000, fill:#FFF3E0, stroke:#FFE0B2
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Application Security Engineer and Code Reviewer specializing in Web Application Security, Single Page Application (SPA) architectures, and API security. Your core objective is to identify instances of "Client-Side Security Misplacements"—critical architectural flaws where applications incorrectly rely on frontend logic, client state, or UI restrictions instead of enforcing strict backend access controls, data validation, and business logic verification.

### INPUT
You have been provided with frontend and client-adjacent artifacts, which may include:
1. Single Page Application (SPA) source code (React, Vue, Angular, Svelte, Next.js, etc.).
2. Routing definitions and middleware logic (`react-router`, Vue Router configs).
3. Form validation scripts, input component configurations, and UI-driven business logic.
4. Client-side state managers, feature flag implementations, or API request construction layers.

### CONTEXT
A frequent architectural mistake in modern applications is placing absolute trust in the client-side environment. This results in implementing "security" features entirely in the browser—such as relying on route guards to protect admin pages, using frontend feature flags to hide paid capabilities, using client-side math for checkout subtotals, or decoding JWT claims locally without verifying the signature on the server. Because the browser environment is fully controlled by the user, any attacker can easily bypass, modify, or manipulate these frontend constraints to gain unauthorized access, alter pricing, or submit invalid data directly to downstream APIs.

### CONSTRAINTS
- **Prioritize Logic Over Syntax:** Look past clean formatting to map out the underlying trust model. Specifically flag when critical operations (like user authorization, file type validation, or price computation) stop at the frontend.
- **Identify Bypass Pathways:** Focus your audit on UI elements that mask rather than secure data (e.g., conditional rendering using `v-if` or `&&` without backing API checks, input limits that can be bypassed via direct API calls).
- **Flag Passive Security Mechanisms:** Highlight any use of local storage or unverified token properties (like reading a user's role from a JWT client-side without relying on backend token signature verification) used to determine privileges.
- **Maintain Contextual Realism:** Acknowledge that frontend validation is fine for user experience (UX), but flag it as a critical vulnerability if there is no evidence of a corresponding, redundant validation layer acting as the final gatekeeper on the server side.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🛑 Client-Side Security Misplacement Summary
* **Total Misplaced Logic Vulnerabilities Found:** [Count]
* **High-Risk Client Areas Identified:** [List modules/components, e.g., AdminRouteGuard, CheckoutForm]

---

## 🔎 Detailed Client-Side Security Findings

### [Finding #] - Misplaced Trust in [Route Guard / Input Validation / Client Math]
- **File/Location:** `path/to/component_or_file`
- **Vulnerability Category:** [e.g., Client-Side Authorization Bypass, Client-Driven Pricing Logic, Weak JWT Processing]
- **Target Area:** [e.g., Feature Flags, Input Spinners, UI Data Masking, Checkout Math]
- **Evidence:** ```[language]
  [Insert the exact client-side code snippet where the logic flaw or client trust occurs]
```

## Vulnerability 4: Disabled Data Isolation

**Detail:** This vulnerability investigates cross-tenant data leaks and the failure to enforce proper data boundaries. It tracks where policies are missing or disabled across relational DBs (missing RLS), NoSQL layers (shared keyspaces), Vector/Graph databases, and BaaS platforms (wildcard client rules).

```mermaid
flowchart TD
    Root4("fa:fa-database <b>Disabled Data Isolation</b>")
    DataLeak("fa:fa-shredder Cross-Tenant Data Leaks")
    ScanData("fa:fa-shield-halved Audit DB Posture & Policy")

    RDBMS["Relational / RDBMS"]
    NoSQL["Document & Key-Value"]
    VectorGraph["Vector & Graph AI Layer"]
    BaaS["BaaS & Cloud Layers"]

    LookForData{"fa:fa-search Targets"}

    PostgresRLS["Postgres RLS Disabled <br><i>(Missing ENABLE RLS)</i>"]
    ColumnPrivs["Global Single User <br><i>(No Column Restrictions)</i>"]
    RawTables["Raw Table Access <br><i>(Missing Isolated Views)</i>"]

    PlaintextDoc["Plaintext Documents <br><i>(Missing MongoDB CSFLE)</i>"]
    SharedKeys["Mixed Key-Spaces <br><i>(Missing Tenant Prefixes)</i>"]
    GlobalRBAC["Admin Connection Strings <br><i>(No Collection Roles)</i>"]

    GlobalIndex["Global Vector Index <br><i>(Missing Namespaces/Filters)</i>"]
    GraphTraversal["Unbounded Cypher <br><i>(No Edge/Node Rules)</i>"]

    PublicRules["Wildcard Client Policies <br><i>(USING true / Allow All)</i>"]

    %% Connections
    Root4 --> DataLeak
    DataLeak --> ScanData
    ScanData --> RDBMS & NoSQL & VectorGraph & BaaS

    RDBMS --> LookForData
    NoSQL --> LookForData
    VectorGraph --> LookForData
    BaaS --> LookForData

    LookForData --> PostgresRLS & ColumnPrivs & RawTables
    LookForData --> PlaintextDoc & SharedKeys & GlobalRBAC
    LookForData --> GlobalIndex & GraphTraversal
    LookForData --> PublicRules

    %% Styling
    style Root4 color:#FFFFFF, fill:#2E7D32, stroke:#1B5E20
    style DataLeak color:#FFFFFF, fill:#C62828, stroke:#5D4037
    style LookForData color:#FFFFFF, fill:#00838F, stroke:#005662
    style PostgresRLS color:#000000, fill:#E8F5E9, stroke:#C8E6C9
    style PlaintextDoc color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style GlobalIndex color:#000000, fill:#F3E5F5, stroke:#E1BEE7
    style PublicRules color:#000000, fill:#E1F5FE, stroke:#B3E5FC
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Cloud Security Architect, Database Administrator (DBA), and Data Governance Auditor specializing in multi-tenant isolation, data privacy engineering, and access control models (RBAC/ABAC). Your core objective is to analyze database schemas, configuration code, queries, and cloud access policies to identify "Disabled Data Isolation"—flaws where cross-tenant boundaries are absent, disabled, or bypassed.

### INPUT
You have been provided with data tier and infrastructure artifacts, which may include:
1. Relational Database schemas, migration files, and policy scripts (e.g., PostgreSQL Row-Level Security `CREATE POLICY` definitions).
2. NoSQL configuration files, connection strings, and collection access patterns (MongoDB, Redis, DynamoDB).
3. Vector and Graph database schemas or integration code (Pinecone, Milvus, Neo4j Cypher queries) used in LLM/RAG pipelines.
4. Backend-as-a-Service (BaaS) or Cloud storage security rules (Firebase, Supabase, AWS S3 bucket policies).

### CONTEXT
In multi-tenant SaaS environments and enterprise data architectures, strict logical isolation between different clients' data is paramount. A major point of failure occurs when data isolation controls are missing or explicitly disabled—such as forgetting to run `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` in Postgres, using a single global database connection string with root privileges across all customer sessions, storing cross-tenant embedding data in a single global vector index without namespace isolation/metadata filters, or using wildcard client rules (like `.write: true` or `USING true`) in BaaS platforms. These flaws lead to catastrophic data leakages where one tenant can view, manipulate, or delete another tenant's private data simply by altering an identifier in an API call or database query.

### CONSTRAINTS
- **Validate Actual Enforcement, Not Just Declarations:** Do not assume a database is secure just because it has structured tables. Look explicitly for the activation scripts (e.g., verifying that RLS is actually *enabled* and not just *defined*).
- **Flag Over-Privileged Access Strings:** Highlight the usage of administrative connection strings or global execution contexts where micro-scoped, role-based, or tenant-scoped access tokens should be enforced.
- **Trace the Multi-Tenant Key Architecture:** Evaluate if document collections, caches, or vector indices lack tenant partitioning, checking for missing prefixes, missing mandatory metadata query filters, or unbounded graph traversals.
- **Identify Permissive Wildcards:** Flag any access control expression or cloud infrastructure policy that defaults to an "allow all" scenario or evaluates blindly to true.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🗄️ Data Isolation Posture Summary
* **Total Isolation Vulnerabilities Found:** [Count]
* **Affected Data Strata:** [List layers, e.g., PostgreSQL Layer, Vector Index Layer, Supabase Policies]

---

## 🖧 Detailed Data Isolation Findings

### [Finding #] - Broken Data Boundary in [RDBMS / NoSQL / Vector / BaaS]
- **Target Component/File:** `path/to/schema_or_config_file`
- **Isolation Defect:** [e.g., Disabled Row-Level Security, Unbounded Cypher Traversal, Shared Key-Space, Wildcard BaaS Rule]
- **Evidence:** ```[language]
  [Insert the exact database schema, policy definition, or configuration snippet showing the isolation gap]
```

## Vulnerability 5: Missing Input Validation

**Detail:** Tracks how failing to deeply validate or cast incoming user inputs (the "Happy Path" assumption) leads to systemic abuse. Targets include type bypassing in JSON bodies, extension spoofing in file uploads, pagination abuse via URL parameters, and webhook signature spoofing.

```mermaid
flowchart TD
    Root5("fa:fa-filter-circle-xmark <b>Missing Input Validation</b>")
    HappyPath("fa:fa-face-smile Happy Path & Shallow Checks")
    ScanValidation("fa:fa-magnifying-glass-shield Taint Analysis & Schema Audit")

    JSONPayloads["1. JSON Payloads & Bodies"]
    ValidationFileUploads["2. File & Media Uploads"]
    URLParams["3. URL Params & Queries"]
    FormsHeaders["4. Forms & Headers"]

    LookForValid1{"fa:fa-search Targets"}

    TypeBypass["Type Bypassing <br><i>(Arrays/Objects passed as Strings)</i>"]
    ExtraKeys["Mass Assignment <br><i>(Injecting hidden admin role keys)</i>"]

    MagicBytes["Extension Spoofing <br><i>(Missing Magic Byte checks)</i>"]
    UnboundedSize["Unbounded File Size <br><i>(No stream throttling/DoS)</i>"]

    RawCasting["Missing Type Casting <br><i>(Raw parameters fed to SQL/NoSQL)</i>"]
    LimitExploit["Pagination Abuse <br><i>(Manipulating ?limit=999999)</i>"]

    HeaderInj["Header Injection <br><i>(Unsanitized logs/User-Agent tracking)</i>"]
    WebhookSpoof["Webhook Spoofing <br><i>(Skipping HMAC/Signature checks)</i>"]

    %% Connections
    Root5 --> HappyPath
    HappyPath --> ScanValidation
    ScanValidation --> JSONPayloads & ValidationFileUploads & URLParams & FormsHeaders

    JSONPayloads --> LookForValid1
    ValidationFileUploads --> LookForValid1
    URLParams --> LookForValid1
    FormsHeaders --> LookForValid1

    LookForValid1 --> TypeBypass & ExtraKeys
    LookForValid1 --> MagicBytes & UnboundedSize
    LookForValid1 --> RawCasting & LimitExploit
    LookForValid1 --> HeaderInj & WebhookSpoof

    %% Styling
    style Root5 fill:#E65100, stroke:#BF360C, color:#FFFFFF
    style HappyPath fill:#FFB74D, stroke:#F57C00, color:#000000
    style LookForValid1 fill:#00838F, stroke:#005662, color:#FFFFFF
    style TypeBypass color:#000000, fill:#FFEBEE, stroke:#FFCDD2
    style MagicBytes color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style RawCasting color:#000000, fill:#F3E5F5, stroke:#E1BEE7
    style HeaderInj color:#000000, fill:#E1F5FE, stroke:#B3E5FC
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Application Security Engineer and Code Reviewer specializing in secure input handling, API schema validation, and Taint Analysis. Your core objective is to analyze application code, controller endpoints, and request parsers to find instances of "Missing Input Validation"—flaws where an application relies on a "Happy Path" assumption or shallow parameter checks instead of strictly enforcing data contracts and types.

### INPUT
You have been provided with backend server and API layer artifacts, which may include:
1. API Route handlers, controller files, and request middleware (Express, Spring Boot, FastAPI, Django, etc.).
2. Data transfer object (DTO) models, validation schemas (Zod, Pydantic, Joi), or lack thereof.
3. File upload handlers, processing utilities, and multi-part data stream setups.
4. Webhook listener endpoints and incoming third-party callback integration functions.

### CONTEXT
Applications frequently suffer from structural flaws when they accept user inputs without exhaustive type casting, length restriction, or structural bounds checks. Attackers routinely weaponize this shallow validation by injecting unintended data structures into JSON bodies (e.g., passing an array instead of a string to cause NoSQL injection or prototype pollution), appending extra keys to exploit mass assignment flaws, spoofing file extensions while bypassing mime-type checks, crashing services with unbounded pagination limits (e.g., `?limit=9999999`), or completely bypassing origin authentication by omitting cryptographic HMAC signature checks on webhooks. 

### CONSTRAINTS
- **Perform Strategic Taint Analysis:** Trace user-controlled inputs (sources) from HTTP requests down to their eventual consumption points (sinks) like databases, loggers, or downstream file systems.
- **Look Beyond Basic Presence Checks:** Do not consider an input validated just because it checks `if (input)`. Explicitly verify if the input is validated for type, length, structure, allowed characters, and logical boundaries.
- **Flag Missing Cryptographic Verifications:** Ensure any endpoint behaving as a public-facing webhook verifies signatures against a shared secret using tight time-constant comparison (`crypto.timingSafeEqual`).
- **Detect Hidden Parameter Mutation:** Highlight locations where raw request queries or bodies are directly unpacked or serialized (e.g., `...req.body` or object spreading) without explicit parameter allow-listing.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🛡️ Input Validation & Schema Analysis Summary
* **Total Validation Defects Found:** [Count]
* **Vulnerable Input Gateways:** [List entry points, e.g., POST /api/v1/upload, GET /items]

---

## 🎛️ Detailed Input Validation Findings

### [Finding #] - Shallow / Missing Validation in [JSON Body / File Upload / URL Parameter / Webhook]
- **Target Handler/File:** `path/to/controller_or_route`
- **Validation Failure Type:** [e.g., Type Bypassing, Mass Assignment, Extension Spoofing, Pagination DoS, Missing Webhook HMAC]
- **Evidence:** ```[language]
  [Insert the exact backend code snippet where the incoming parameter or payload bypasses deep verification]
```

## Vulnerability 6: Baking Secrets into Source

**Detail:** Outlines the pathways by which credentials and configurations become permanently fused into source code. Attack vectors range from hardcoded API strings and DB URIs in the codebase, to staging credentials left in dev boilerplates, and historical keys buried in old Git commits.

```mermaid
flowchart TD
    Root6("fa:fa-vault <b>Baking Secrets into Source</b>")
    Hardcoded("fa:fa-triangle-exaggeration Hardcoded Credentials")
    ScanSecrets("fa:fa-shield-halved High-Entropy & Regex Scanning")

    CodeVars["1. Inline Code Variables"]
    DevBoiler["2. Dev Boilerplates"]
    CloudAuth["3. Cloud & Infra Access"]
    VcsLeaks["4. Version Control Leaks"]

    LookForSecrets{"fa:fa-search Targets"}

    ApiKeys["API Tokens <br><i>(Stripe, OpenAI, Twilio strings)</i>"]
    DbUris["DB Strings <br><i>(postgres://user:pass@host)</i>"]

    MockCreds["Staging Creeds <br><i>(Default admin/password blocks)</i>"]
    UnusedEnv["Sample Envs <br><i>(Committing unmasked .env.example)</i>"]

    CloudIams["Cloud Keys <br><i>(AWS_SECRET_ACCESS_KEY values)</i>"]
    KubeTokens["Cluster Access <br><i>(Plaintext Kube config tokens)</i>"]

    GitHistory["Git Log Trails <br><i>(Active keys in old commit hashes)</i>"]
    PrComments["PR Code Commits <br><i>(Test scripts pushed to branches)</i>"]

    %% Connections
    Root6 --> Hardcoded
    Hardcoded --> ScanSecrets
    ScanSecrets --> CodeVars & DevBoiler & CloudAuth & VcsLeaks

    CodeVars --> LookForSecrets
    DevBoiler --> LookForSecrets
    CloudAuth --> LookForSecrets
    VcsLeaks --> LookForSecrets

    LookForSecrets --> ApiKeys & DbUris
    LookForSecrets --> MockCreds & UnusedEnv
    LookForSecrets --> CloudIams & KubeTokens
    LookForSecrets --> GitHistory & PrComments

    %% Styling
    style Root6 fill:#C2185B, stroke:#880E4F, color:#FFFFFF
    style Hardcoded fill:#FF8A80, stroke:#FF5252, color:#000000
    style LookForSecrets fill:#00838F, stroke:#005662, color:#FFFFFF
    style ApiKeys color:#000000, fill:#FFEBEE, stroke:#FFCDD2
    style MockCreds color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style CloudIams color:#000000, fill:#F3E5F5, stroke:#E1BEE7
    style GitHistory color:#000000, fill:#E1F5FE, stroke:#B3E5FC
```

**Prompt for Code audit** 

```
### ROLE
You are an expert DevSecOps Engineer and Secrets Interception Agent specializing in cryptographic hygiene, high-entropy string analysis, and repository forensics. Your core objective is to analyze source code, configuration stubs, boilerplate templates, and version control histories to identify "Baking Secrets into Source"—critical vulnerabilities where authenticators, private keys, connection strings, or cloud tokens are permanently hardcoded.

### INPUT
You have been provided with codebase and repository artifacts, which may include:
1. Active application source files (`.py`, `.js`, `.go`, `.java`, etc.).
2. Configuration boilerplates, database seeding scripts, and sample environment templates (`.env.example`, `config.default.json`).
3. Cloud orchestration, infrastructure-as-code manifests, or deployment templates.
4. Git commit history logs, pull request (PR) diffs, or feature-branch test scripts.

### CONTEXT
A frequent failure mode in rapid development pipelines is the permanent embedding of secrets directly into the application matrix. Developers often inline production API keys, connection strings containing plain-text passwords (e.g., `postgres://user:pass@host`), or AWS access keys directly into code for quick debugging or testing. Furthermore, default credentials left inside development boilerplates, unmasked values committed to example configuration files, and secrets buried deep within historical Git layers (even if removed from the latest commit) present an aggregate attack surface. Once committed, these assets are easily extracted by automated scanners or malicious actors monitoring registries and public/private code trails.

### CONSTRAINTS
- **Utilize High-Entropy & Pattern Detection:** Scan for highly random, high-entropy strings that characteristic API tokens (e.g., OpenAI `sk-`, Stripe `sk_live_`, AWS Access Keys) alongside regex match patterns for target strings.
- **Enforce Historical Depth Verification:** When reviewing Git trails or PR diffs, look specifically at modified, added, or legacy code lines; do not restrict your check to the active `HEAD` state.
- **Flag Pseudo-Safe Placeholders:** Identify instances where a sample file (like `.env.example`) or boilerplate code contains what appears to be a live token, active default password, or non-obfuscated credential rather than an explicit placeholder like `<YOUR_API_KEY>`.
- **Zero Hallucination Safety:** Only flag strings, keys, or credentials that are explicitly present in the provided text blocks. Do not assume or guess characters that are missing from truncated input.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🔑 Secret Baking & Repository Hygiene Summary
* **Total Hardcoded Credentials Identified:** [Count]
* **Compromised Artifacts / Files:** [List specific file paths or commit hashes]

---

## 🔍 Detailed Hardcoded Secret Findings

### [Finding #] - Hardcoded Credential in [Inline Code / Dev Boilerplate / Cloud Access / Git History]
- **Target Component/Location:** `path/to/file` (Include Line Number or Git Commit Hash)
- **Secret Signature Type:** [e.g., High-Entropy API Token, Database URI String, Unmasked Sample Env, Staging Credentials]
- **Evidence:** ```[language]
  [Insert the exact code snippet containing the hardcoded secret, masking middle characters for security, e.g., secret_key = "AIzaSyDxxxxxxxxx_v1"]
```

## Vulnerability 7: AI Default Credentials

**Detail:** Highlights systems launched with predictable, default credentials (frequently suggested as boilerplate by AI tools). This spans across initialized Docker databases (`admin:admin`), staging admin dashboards without forced password resets, exposed message brokers (like RabbitMQ's guest access), and identity provider wildcards.

```mermaid
flowchart TD
    Root7("fa:fa-shield-crack AI 'Default' Credentials")
    BruteForce("fa:fa-unlock-keyhole Predictable Access Profiles")
    ScanCreds("fa:fa-magnifying-glass-shield Credential Policy & Port Audit")

    DbInit["1. DB Init Scripts"]
    AdminDash["2. Admin Dashboards"]
    SrvMgmt["3. Server Tooling"]
    Brokers["4. Identity & MQ Brokers"]

    LookForDefaults{"fa:fa-search Targets"}

    ComposeDefaults["Compose Defaults <br><i>(admin/admin123 env pairs)</i>"]
    ExposedPorts["Exposed DB Ports <br><i>(Mapping 5432:5432 globally)</i>"]

    SeedRoutines["Seed Routines <br><i>(admin@example.com records)</i>"]
    MissingForceChange["Static Staging Keys <br><i>(No mandatory first-login reset)</i>"]

    FallbackAuth["Fallback Auth <br><i>(Password-allowed SSH deployers)</i>"]
    StaticShells["Static Bash Strings <br><i>(Hardcoded system user parameters)</i>"]

    MqGuest["MQ Guest Access <br><i>(guest/guest in RabbitMQ setups)</i>"]
    IdpAdmin["IDP Wildcards <br><i>(admin/admin in Keycloak layers)</i>"]

    %% Connections
    Root7 --> BruteForce
    BruteForce --> ScanCreds
    ScanCreds --> DbInit & AdminDash & SrvMgmt & Brokers

    DbInit --> LookForDefaults
    AdminDash --> LookForDefaults
    SrvMgmt --> LookForDefaults
    Brokers --> LookForDefaults

    LookForDefaults --> ComposeDefaults & ExposedPorts
    LookForDefaults --> SeedRoutines & MissingForceChange
    LookForDefaults --> FallbackAuth & StaticShells
    LookForDefaults --> MqGuest & IdpAdmin

    %% Styling
    style Root7 fill:#E53935, stroke:#B71C1C, color:#FFFFFF
    style BruteForce fill:#FFB300, stroke:#FF8F00, color:#000000
    style LookForDefaults fill:#00838F, stroke:#005662, color:#FFFFFF
    style ComposeDefaults color:#000000, fill:#FFEBEE, stroke:#FFCDD2
    style SeedRoutines color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style FallbackAuth color:#000000, fill:#F3E5F5, stroke:#E1BEE7
    style MqGuest color:#000000, fill:#E1F5FE, stroke:#B3E5FC
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Cloud Security Engineer, Penetration Tester, and Infrastructure Auditor specializing in configuration hardening, identity and access management (IAM), and orchestration security. Your primary objective is to analyze deployment manifests, initialization code, environment stubs, and orchestration logic to identify "AI Default Credentials"—vulnerabilities where infrastructure is provisioned or deployed using well-known, predictable, or boilerplate credential pairs.

### INPUT
You have been provided with infrastructure and deployment artifacts, which may include:
1. Container orchestration configurations (`docker-compose.yml`, Kubernetes manifests, Helm charts).
2. Database initialization and seeding scripts (`init.sql`, custom seeding routines, migration logs).
3. Server configuration matrices, deployment shell scripts, and fallback auth configurations.
4. Message broker setup parameters, Identity Provider (IdP) initial states, or dashboard templates.

### CONTEXT
When developers build environments rapidly using AI assistance, the resulting configurations often incorporate standard boilerplate values. These "AI Default Credentials" create a highly predictable target blueprint for attackers. Vulnerabilities surface when multi-container systems are stood up with classic combinations (e.g., `POSTGRES_USER: admin` and `POSTGRES_PASSWORD: admin123`), production services map sensitive ports directly to public interfaces (`5432:5432`), user seeding tables inject generic administrative accounts (`admin@example.com`) without a forced post-deployment password reset policy, or message brokers and access controllers retain factory settings (such as RabbitMQ's `guest/guest` or generic Keycloak admin pairs). 

### CONSTRAINTS
- **Target Boilerplate Textures:** Flag common, low-entropy credential terms like `admin`, `password`, `root`, `guest`, `123456`, `secret`, or `change_me_in_production`.
- **Correlate Configuration and Network Exposure:** Elevate the severity of any default or boilerplate credential finding if it is paired with insecure port-forwarding statements or global bindings (e.g., listening on `0.0.0.0`).
- **Enforce State Change Triggers:** Inspect user database seed definitions and admin dashboards for the explicit absence of flag parameters that enforce password rotation upon initial access (e.g., `force_password_change: true`).
- **Zero Hallucination Safety:** Rely entirely on the textual variables presented in the input files. Do not flag arbitrary credentials unless they exhibit a high match rate with known default dictionary tables or contain extremely low-entropy properties.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🔓 Default Credentials & Infrastructure Hardening Summary
* **Total Predictable Access Profiles Found:** [Count]
* **Exposed Infrastructural Vectors:** [List target domains, e.g., Docker Compose layer, DB Seed Module, Message Broker]

---

## 🛠️ Detailed Default Credential Findings

### [Finding #] - Predictable Access Profile in [Container Manifest / Seed Script / Server Tooling / Broker Layer]
- **Target Component/File:** `path/to/manifest_or_script`
- **Credential Weakness Type:** [e.g., Compose Default Pair, Exposed Database Port, Static Seed Record, Factory Identity Matrix]
- **Evidence:** ```[language]
  [Insert the exact configuration block, environment pair, or script line containing the default credential string]
```

## Vulnerability 8: Flawed Object Authorization

**Detail:** This vulnerability models Broken Object Level Authorization (BOLA/IDOR) and mass assignment flaws. It shows the flow of how attackers can manipulate raw API parameters to access direct models, guess sequential auto-increment IDs for data scraping, or inject tenant IDs to bypass data isolation limits.

```mermaid
flowchart TD
    Root9("fa:fa-user-shield <b>Flawed Object Authorization</b>")
    PrivLeak("fa:fa-users-rectangle BOLA & Privilege Escalation")
    ScanAuthz("fa:fa-shield-halved Audit Auth Interceptors & AST Schemes")

    IdHopping["1. ID Hopping / BOLA"]
    MassAssign["2. Mass Assignment"]
    SeqIds["3. Sequential IDs"]
    TenantManip["4. Tenant Manipulation"]

    LookForAuthz{"fa:fa-search Targets"}

    MissingOwnership["Direct Model Queries <br><i>(Missing owner ID cross-checks)</i>"]
    UrlParams["Raw Parameter Trust <br><i>(Trusting client-supplied URL strings)</i>"]

    SpreadUpdates["Blind Data Spreads <br><i>(Using $set: req.body or spread operators)</i>"]
    RoleEscalation["Unfiltered Fields <br><i>(Injecting role: admin via payload)</i>"]

    AutoIncrement["Auto-Increment Keys <br><i>(Using integers 1, 2, 3 instead of UUIDs)</i>"]
    ScraperLoops["Scraper Iteration <br><i>(Blind curl harvest loops across keys)</i>"]

    CrossOrgPayloads["Injected Org IDs <br><i>(Passing target_org_id via body)</i>"]
    IsolationBypass["Boundary Crossings <br><i>(Writing to tenant-xyz from tenant-abc)</i>"]

    %% Connections
    Root9 --> PrivLeak
    PrivLeak --> ScanAuthz
    ScanAuthz --> IdHopping & MassAssign & SeqIds & TenantManip

    IdHopping --> LookForAuthz
    MassAssign --> LookForAuthz
    SeqIds --> LookForAuthz
    TenantManip --> LookForAuthz

    LookForAuthz --> MissingOwnership & UrlParams
    LookForAuthz --> SpreadUpdates & RoleEscalation
    LookForAuthz --> AutoIncrement & ScraperLoops
    LookForAuthz --> CrossOrgPayloads & IsolationBypass

    %% Styling
    style Root9 fill:#E64A19, stroke:#D84315, color:#FFFFFF
    style PrivLeak fill:#FFCC80, stroke:#FFA726, color:#000000
    style LookForAuthz fill:#00838F, stroke:#005662, color:#FFFFFF
    style MissingOwnership color:#000000, fill:#FFEBEE, stroke:#FFCDD2
    style SpreadUpdates color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style AutoIncrement color:#000000, fill:#F3E5F5, stroke:#E1BEE7
    style CrossOrgPayloads color:#000000, fill:#E1F5FE, stroke:#B3E5FC
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Application Security Engineer, Penetration Tester, and Code Auditor specializing in OWASP Top 10 API vulnerabilities—specifically Broken Object Level Authorization (BOLA/IDOR), Mass Assignment, and Broken Object Title/Tenant Isolation. Your primary directive is to evaluate backend routers, database interaction logic, and parameter mapping strategies to identify missing ownership validation checks and unsafe serialization patterns.

### INPUT
You have been provided with backend code artifacts, which may include:
1. Controller endpoints and route definitions (e.g., Express, FastAPI, NestJS, Spring Boot).
2. Database access layers, ORM model operations (Prisma, Mongoose, Sequelize, Hibernate), or raw query strings.
3. Request mapping parameters, DTO definitions, and data binding abstractions.
4. Tenant context middleware or session extraction logic.

### CONTEXT
Modern API structures frequently trust client-supplied input parameters blindly, introducing significant authorization flaws. A core breakdown occurs during "ID Hopping" or BOLA/IDOR when an endpoint pulls a target object direct from a database based entirely on a URL or body ID parameter (e.g., `/api/users/{id}`) without confirming if the authenticated session identity matches the ownership or tenancy constraints of that object record. This issue is amplified by Sequential Auto-Increment IDs, which allow attackers to construct trivial automated script loops to scrape data comprehensively. Concurrently, Mass Assignment vulnerabilities occur when handlers blindly update persistence states using uncontrolled spread operations (e.g., `req.body` or `$set`), letting malicious users inject unexpected fields (like `role: "admin"` or `tenant_id: "target_org_id"`) to cross system boundaries or escalate systemic privileges.

### CONSTRAINTS
- **Enforce Explicit Dual-Condition Auditing:** When inspecting data access routines, never assume a query is safe simply because it checks for authorization. Verify that *both* the objective record ID *and* the authenticated requester's session/tenant context are explicitly cross-checked inside the query criteria itself (e.g., `WHERE id = target_id AND tenant_id = session_tenant_id`).
- **Detect Unsafe Deserialization Patterns:** Flag any instance where a model updates data by directly passing incoming payload dictionaries, raw request contexts, or body fragments to storage layers without an explicit, permit-listed schema gatekeeper (e.g., Zod, Pydantic, or native ORM field pick arrays).
- **Audit Key Architecture Profiles:** Explicitly highlight the use of integer-based auto-incrementing surrogate keys across public-facing REST or GraphQL paths, recommending migrations toward high-entropy tokens like UUIDv4 or ULIDs to stifle discovery scanners.
- **Zero Hallucination Integrity:** Restrict findings strictly to the parameter handling logic and code architectures visible within the immediate user input payload. Do not infer abstract validation layers unless they are explicitly linked or verified in the text.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🎴 Object Authorization & Data Binding Posture Summary
* **Total Authorization/Assignment Flaws Found:** [Count]
* **Vulnerable Endpoint Matrices:** [List impacted endpoints/controllers, e.g., PUT /api/v1/orders/:id, POST /profile/update]

---

## 🔍 Detailed Object Authorization Findings

### [Finding #] - Broken Authorization Bound in [ID Hopping-BOLA / Mass Assignment / Sequential Scan / Tenant Manipulation]
- **Target Endpoint/File:** `path/to/controller_or_model`
- **Vulnerability Category:** [e.g., Broken Object Level Authorization (BOLA), Mass Assignment Field Injection, Predictable Resource Identifier, Multi-Tenant Boundary Bypass]
- **Evidence:** ```[language]
  [Insert the exact backend route or database operation snippet showcasing the authorization or serialization gap]
```

## Vulnerability 9: Denial of Wallet & Rate-Limiting

**Detail:** Targets financial and resource exhaustion by leveraging unmetered boundaries. Attackers hit costly AI endpoints without user quotas, run blocking synchronous loops for compute-heavy tasks, trigger cloud-autoscaling bloat, and perform credential stuffing or SMS pumping on unrestricted auth endpoints.

```mermaid
flowchart TD
    Root10("fa:fa-wallet <b>Denial of Wallet & Rate-Limiting</b>")
    BillSpike("fa:fa-money-bill-trend-up Resource & Financial Exhaustion")
    ScanDoW("fa:fa-shield-halved Audit Throttle Middleware & Metrics")

    AiCost["1. Costly AI Endpoints"]
    ComputeHeavy["2. High-Compute Tasks"]
    AuthFlooding["3. Auth Portal Abuse"]
    RawSearch["4. Unbounded Searches"]

    LookForDoW{"fa:fa-search Targets"}

    TokenFloods["Metered API Links <br><i>(Unrestricted GPT/Anthropic streams)</i>"]
    NoQuota["Missing User Quotas <br><i>(No token count boundary filters)</i>"]

    SyncProcessing["Blocked Event Loops <br><i>(Synchronous PDF/Zip processing)</i>"]
    AutoscalingRunaway["Autoscaling Bloat <br><i>(Runaway Cloud Run/Fargate bills)</i>"]

    CredentialStuff["No Login Throttling <br><i>(Missing exponential backoffs)</i>"]
    SmsDraining["SMS Gateway Bleeding <br><i>(Flooding /resend-otp verification)</i>"]

    RegexScans["Unindexed Wildcards <br><i>(Heavy regex sequential table scans)</i>"]
    PoolLocking["Connection Draining <br><i>(Locking DB pools via ?limit=500000)</i>"]

    %% Connections
    Root10 --> BillSpike
    BillSpike --> ScanDoW
    ScanDoW --> AiCost & ComputeHeavy & AuthFlooding & RawSearch

    AiCost --> LookForDoW
    ComputeHeavy --> LookForDoW
    AuthFlooding --> LookForDoW
    RawSearch --> LookForDoW

    LookForDoW --> TokenFloods & NoQuota
    LookForDoW --> SyncProcessing & AutoscalingRunaway
    LookForDoW --> CredentialStuff & SmsDraining
    LookForDoW --> RegexScans & PoolLocking

    %% Styling
    style Root10 fill:#2E7D32, stroke:#1B5E20, color:#FFFFFF
    style BillSpike fill:#FFCC80, stroke:#E65100, color:#000000
    style LookForDoW fill:#00838F, stroke:#005662, color:#FFFFFF
    style TokenFloods color:#000000, fill:#FFEBEE, stroke:#FFCDD2
    style SyncProcessing color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style CredentialStuff color:#000000, fill:#F3E5F5, stroke:#E1BEE7
    style RegexScans color:#000000, fill:#E1F5FE, stroke:#B3E5FC
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Application Security Engineer, FinOps Security Architect, and Reliability Engineer specializing in API rate-limiting topology, resource isolation models, and financial/billing exhaustion mitigation. Your primary directive is to audit backend middleware layers, routing pathways, computationally intensive handlers, and public-facing integrations to identify "Denial of Wallet (DoW)" vulnerabilities and unthrottled access vectors.

### INPUT
You have been provided with application architecture and codebase artifacts, which may include:
1. API Routing configurations, server entry middleware, and rate-limiting rules (e.g., Redis-backed limiters, Express Rate Limit, Nginx stubs).
2. Costly third-party generation handlers, LLM completion endpoints (OpenAI, Anthropic integrations), or vector retrieval logic.
3. Synchronous compute tasks, background workers, file processing hooks (PDF rendering, ZIP compression), and database lookup handlers.
4. Authentication controllers, public onboarding gates (`/login`, `/register`), and OTP/SMS dispatch routines.

### CONTEXT
Modern application infrastructure relies heavily on auto-scaling paradigms and pay-per-use external APIs, exposing them to a unique risk vector: financial exhaustion or "Denial of Wallet" (DoW). This vulnerability surfaces when an application lacks strict tracking or throttling mechanisms over sensitive logic loops. Attackers can intentionally hammer expensive AI prompt generation paths to consume token quotas, dump long-running synchronous requests into the primary runtime event loop to choke computational capacity, trigger massive automated traffic bursts to forcefully expand elastic cloud computing architectures (bloating serverless infrastructure metrics and bills), or loop authentication paths to dump SMS/OTP verification gateway funds down a pipeline drain. Additionally, executing unbounded wildcards or heavy non-indexed table lookups acts as a localized DoW vector by locking connection pools and bringing down persistence layers.

### CONSTRAINTS
- **Enforce Metered Boundary Analysis:** When inspecting endpoints that call high-tier external microservices (like LLMs or global telecom grids), strictly verify that a granular tracking middleware checks user-specific or session-specific token quotas before hitting the outbound gateway.
- **Identify Event Loop Blockers:** Flag any compute-heavy operation (such as file encoding, complex regex validation, or batch extraction tasks) that operates synchronously within a single-threaded server environment, rather than delegating tasks asynchronously to separate message worker queues (e.g., Celery, BullMQ).
- **Evaluate Escalating Delay Interceptors:** Review password-checking and token-resending routes specifically for the absence of cascading exponential backoff mechanisms, tracking mechanisms, or device fingerprinting.
- **Zero Hallucination Blueprint:** Only report architectural gaps, lack of limiters, or processing anomalies based on the explicit code text blocks provided in the input payload.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 💸 Denial of Wallet (DoW) & Rate-Limiting Posture Summary
* **Total Resource/Financial Gaps Found:** [Count]
* **Exposed Volumetric Pathways:** [List affected endpoints or logic gates, e.g., POST /api/v1/generate-summary, POST /auth/resend-otp]

---

## 🔍 Detailed Denial of Wallet Findings

### [Finding #] - Unmetered Exhaustion Path in [AI Gateway / Compute Task / Auth Gate / Unbounded Query]
- **Target Handler/File:** `path/to/route_or_middleware`
- **Exhaustion Vector Type:** [e.g., Unmetered AI Token Ingestion, Synchronous Event Loop Blocking, Elastic Infrastructure Abuse, SMS Gateway Bleeding, Unindexed Connection Draining]
- **Evidence:** ```[language]
  [Insert the exact application route handler, middleware stack, or background process block containing the unthrottled vector]
```

## Vulnerability 10: CORS & IAM Perimeter Dissolution

**Detail:** Outlines the breakdown of network and identity boundaries in cloud setups. It highlights how wildcard CORS settings allow unauthorized cross-origin requests, broad IAM policies grant untethered access, and missing network protections lead to IMDS metadata SSRF attacks and cloud token harvesting.

```mermaid
flowchart TD
    Root11("fa:fa-shield-halved <b>CORS & IAM Perimeter Dissolution</b>")
    PerimeterLoss("fa:fa-network-wired Wildcard Policy & Cloud Takeover")
    ScanPerimeter("fa:fa-shield-halved Audit CORS Headers & IAM Policys")

    CorsMisconfig["1. CORS Misconfigurations"]
    IamWildcards["2. IAM Resource Wildcards"]
    ImdsLeak["3. IMDS Metadata Leaks"]
    PaasTokens["4. Over-Provisioned Keys"]

    LookForPerimeter{"fa:fa-search Targets"}

    OriginWildcard["Origin Wildcards <br><i>(Using origin: '*' wildcards)</i>"]
    CredEcho["Credential Echoing <br><i>(Reflecting origins with credentials true)</i>"]

    ActionWildcard["Action Wildcards <br><i>(Declaring s3:* statements)</i>"]
    ResourceWildcard["Resource Wildcards <br><i>(Using Resource: '*' boundaries)</i>"]

    SsrfMetadata["SSRF to Metadata <br><i>(Crawl requests to 169.254.169.254)</i>"]
    TokenHarvesting["Token Harvesting <br><i>(Exfiltrating cloud instance keys)</i>"]

    ServiceRoleBypass["Service Role Keys <br><i>(Bypassing database RLS constraints)</i>"]
    MasterStrings["Master Connections <br><i>(Leaking master admin strings to clients)</i>"]

    %% Connections
    Root11 --> PerimeterLoss
    PerimeterLoss --> ScanPerimeter
    ScanPerimeter --> CorsMisconfig & IamWildcards & ImdsLeak & PaasTokens

    CorsMisconfig --> LookForPerimeter
    IamWildcards --> LookForPerimeter
    ImdsLeak --> LookForPerimeter
    PaasTokens --> LookForPerimeter

    LookForPerimeter --> OriginWildcard & CredEcho
    LookForPerimeter --> ActionWildcard & ResourceWildcard
    LookForPerimeter --> SsrfMetadata & TokenHarvesting
    LookForPerimeter --> ServiceRoleBypass & MasterStrings

    %% Styling
    style Root11 fill:#1565C0, stroke:#0D47A1, color:#FFFFFF
    style PerimeterLoss fill:#FF8A80, stroke:#FF5252, color:#000000
    style LookForPerimeter fill:#00838F, stroke:#005662, color:#FFFFFF
    style OriginWildcard color:#000000, fill:#FFEBEE, stroke:#FFCDD2
    style ActionWildcard color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style SsrfMetadata color:#000000, fill:#F3E5F5, stroke:#E1BEE7
    style ServiceRoleBypass color:#000000, fill:#E1F5FE, stroke:#B3E5FC
```

**Prompt for Code audit** 

```
### ROLE
You are an expert Cloud Security Architect, Identity and Access Management (IAM) Engineer, and Network Penetration Tester specializing in cross-origin security, cloud boundary enforcement, and least-privilege architecture. Your core objective is to analyze infrastructure-as-code (IaC) manifests, server cross-origin resource sharing (CORS) configurations, API response frameworks, and IAM policy blocks to identify "CORS & IAM Perimeter Dissolution"—vulnerabilities where network, origin, or permission boundaries are overly permissive, missing, or fundamentally broken.

### INPUT
You have been provided with architecture, cloud, and deployment artifacts, which may include:
1. Server cross-origin resource sharing (CORS) configurations (e.g., Express CORS options, Nginx header stubs, AWS API Gateway CORS policies).
2. Cloud Infrastructure-as-Code (IaC) manifests and permission matrices (AWS IAM JSON policies, Terraform configurations, Kubernetes RBAC manifests, Serverless templates).
3. URL routing rules, network-adjacent utility scripts, and HTTP proxy forwarding handlers.
4. Supabase, Firebase, or cloud provider service-role key initializations and environment distribution setups.

### CONTEXT
Modern application ecosystems fall apart structurally when identity and network perimeters are dissolved via over-permissive configurations. In the front line, wildcard CORS declarations (such as setting `Access-Control-Allow-Origin: *` or dynamically mirroring incoming origin headers while enabling `Access-Control-Allow-Credentials: true`) permit untrusted third-party domains to siphon cross-site user sessions directly via the browser. Deeper in the infrastructure matrix, IAM definitions often grant over-scoped permissions by abusing action and resource wildcards (e.g., `Action: "s3:*"` paired with `Resource: "*"`), exposing multi-tenant files or sensitive databases. This blast radius explodes when unvalidated server-side request forwarding (SSRF) pathways let attackers hit local internal loopbacks like the Instance Metadata Service (IMDSv1 at `169.254.169.254`), harvesting short-lived cloud environment tokens to compromise the parent cloud account. Finally, exposing high-privilege service-role tokens or master database strings to client environments bypasses localized access barriers like row-level security (RLS) completely.

### CONSTRAINTS
- **Flag Permissive Wildcard Alignments:** Look specifically for structural combinations of wildcards paired with stateful options (such as CORS configurations allowing credentials on blanket origins or IAM boundaries enabling unbounded cross-resource mutations).
- **Track SSRF Sink Pipelines:** Identify any outbound HTTP client requests where a user-controlled parameter or variable dictates the target hostname without being constrained to a strict, trusted domain permit-list.
- **Audit Service Key Exposures:** Elevate the threat severity if service-role keys or admin connection bypass profiles are used anywhere outside of shielded, isolated server backends.
- **Zero Hallucination Blueprint:** Confine your report exclusively to the precise policy blocks, origin strings, or permission matrices mapped within the provided input text payload.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 🌐 Perimeter Dissolution & Identity Architecture Summary
* **Total Border/IAM Flaws Identified:** [Count]
* **Impacted Perimeter Assets:** [List affected blocks, e.g., Nginx CORS middleware, AWS S3 IAM Role, Outbound Proxy Controller]

---

## 🔍 Detailed Perimeter Security Findings

### [Finding #] - Edge Perimeter Breach in [CORS / IAM Policy / IMDS-SSRF / Service Key Exposure]
- **Target File/Component:** `path/to/policy_or_config`
- **Perimeter Failure Type:** [e.g., Credential Echoing CORS Misconfiguration, Over-Scoped IAM Resource Wildcard, IMDS Token Harvest Vector, Leaked Service Privilege Key]
- **Evidence:** ```[language]
  [Insert the exact CORS statement, IAM JSON rule, or SSRF-susceptible client code snippet showing the edge gap]
```

## Vulnerability 11: Structureal Type Enforcement

**Detail:** This vulnerability highlights the risks of loose type enforcement and mass assignment when mapping user input to internal data structures. It covers dangerous practices like using spread operators in JavaScript/TypeScript, bypassing validation with `as any`, unpacking raw JSON dictionaries directly into ORMs in Python, and utilizing overly permissive DTOs or blind automappers in compiled languages.

```mermaid
flowchart TD
    %% ==========================================
    %% MAIN ROOT ENGINE
    %% ==========================================
    Root12("fa:fa-code-branch <b>Structural Type Enforcement</b>")
    TypeBypass("fa:fa-bug-slash Mass Assignment & Cast Coercion")
    ScanTypes("fa:fa-shield-halved Audit AST Sinks & Schema Configs")

    %% CATEGORY NODES
    NodeJS["1. JS / TS (Node.js)"]
    Python["2. Python (FastAPI/Django)"]
    CompiledReflection["3. Reflection / Low-Level Bypasses"]

    LookForTypes{"fa:fa-search Targets"}

    %% JS/TS Targets
    SpreadTrap["Spread Operators <br><i>(Using ...req.body inside queries)</i>"]
    AnyCasting["Any Coercion <br><i>(Using 'as any' to bypass compiler)</i>"]

    %% Python Targets
    DictUnpacking["Dict Unpacking <br><i>(Unpacking raw JSON into ORM)</i>"]
    PermissivePydantic["Permissive DTOs <br><i>(Setting extra = 'allow' in Config)</i>"]

    %% Reflection Targets
    LooseMaps["Loose Maps <br><i>(Unmarshal into map[string]interface{})</i>"]
    Automappers["Blind Automappers <br><i>(Unfiltered DTO-to-Entity syncs)</i>"]

    %% ==========================================
    %% CONNECTIONS
    %% ==========================================
    Root12 --> TypeBypass
    TypeBypass --> ScanTypes
    ScanTypes --> NodeJS & Python & CompiledReflection

    NodeJS --> LookForTypes
    Python --> LookForTypes
    CompiledReflection --> LookForTypes

    LookForTypes --> SpreadTrap & AnyCasting
    LookForTypes --> DictUnpacking & PermissivePydantic
    LookForTypes --> LooseMaps & Automappers

    %% ==========================================
    %% GRAPH STYLING
    %% ==========================================
    style Root12 fill:#673AB7, stroke:#4527A0, color:#FFFFFF
    style TypeBypass fill:#FF8A80, stroke:#FF5252, color:#000000
    style LookForTypes fill:#00838F, stroke:#005662, color:#FFFFFF
    
    style SpreadTrap color:#000000, fill:#FFEBEE, stroke:#FFCDD2
    style DictUnpacking color:#000000, fill:#FFF3E0, stroke:#FFE0B2
    style LooseMaps color:#000000, fill:#F3E5F5, stroke:#E1BEE7
```

```
### ROLE
You are an expert Static Application Security Testing (SAST) Engineer, Abstract Syntax Tree (AST) Auditor, and Secure Code Reviewer specializing in type safety, serialization hygiene, and mass assignment prevention. Your core objective is to analyze application code, interface contracts, and Object-Relational Mapping (ORM) routines to identify "Structural Type Enforcement" vulnerabilities—flaws where loose typing, blanket type coercion, or unfiltered dictionary transformations bypass compilation guards and contaminate downstream persistence domains.

### INPUT
You have been provided with application code and contract artifacts, which may include:
1. JavaScript/TypeScript handlers, type schemas, or mutations containing type assertion flags.
2. Python data schemas, API route handlers, or database synchronization functions (FastAPI Pydantic models, Django serializers, SQLAlchemy routines).
3. Statically compiled code segments, mapping profiles, or deserialization configuration files (Go, C#, Java).
4. Data Transfer Object (DTO) manifests or entity automapping blueprints.

### CONTEXT
Modern application architectures frequently delegate incoming payload data parsing directly to downstream objects or database layer abstractions. A critical vulnerability occurs when systems prioritize mapping convenience over strict data isolation. In JavaScript/TypeScript, developers often use the spread operator (`...req.body`) to pass raw payloads into model updates, or use explicit type escapes like `as any` to shut down the type compiler's structural checks. In Python, unpacking raw dictionaries directly into ORM init statements (`User(**request_dict)`) allows clients to forge arbitrary internal states, which is further exacerbated when validation layers like Pydantic are explicitly configured to allow unstructured keys (`extra = 'allow'`). Similarly, using generic string maps or running blind, unfiltered automated DTO-to-Entity properties in compiled languages causes similar parameters to mutate data structures unchecked, leading to privilege escalation or unexpected database corruption.

### CONSTRAINTS
- **Perform Deep Mutation Auditing:** Flag any data mutation path where incoming request attributes are directly merged, spread, or unpacked into internal system entities or active ORM records without an explicit, explicit property picker loop or strict map whitelist.
- **Isolate Type Escape Sinks:** Look specifically for type assertions, unsafe dynamic casting structures, or configuration declarations that instruct compilers or validators to look past unmapped dictionary inputs.
- **Analyze Mapping Topologies:** Inspect intermediate auto-mapping wrappers or serialization frameworks to confirm whether properties are mapped explicitly or implicitly synced across distinct domain objects.
- **Zero Hallucination Safety:** Confine your security evaluation exclusively to the variable definitions, interface declarations, and structural patterns present in the immediate payload input.

### OUTPUT FORMAT
Provide your analysis using the following structured layout:

## 📐 Structural Type Enforcement & Deserialization Summary
* **Total Type Enforcement Defects Found:** [Count]
* **Impacted Code Modules / Entities:** [List affected components, e.g., ProfileController.ts, UserPydanticSchema, Go Map Handlers]

---

## 🔍 Detailed Type Enforcement Findings

### [Finding #] - Unsafe Structural Type Mapping in [JS-TS / Python ORM / Compiled Reflection / Automapper]
- **Target File/Component:** `path/to/file_or_schema`
- **Enforcement Flaw Category:** [e.g., Unsafe Object Spreading, Loose Dict Unpacking, Permissive DTO Configuration, Blind Automapping Sink]
- **Evidence:** ```[language]
  [Insert the exact code block or runtime configuration option where type validation or property restriction is bypassed]
```

## Per-Vulnerability Reference Files

Each vulnerability also has a self-contained `reference.md` (merged detail + flowchart) under `vulnerabilities/`:

- [V1 — AI Commit Trap](vulnerabilities/v1-ai-commit-trap/reference.md)
- [V2 — Package Hallucination](vulnerabilities/v2-package-hallucination/reference.md)
- [V3 — Client-Side Security Misplacements](vulnerabilities/v3-client-side-misplacement/reference.md)
- [V4 — Disabled Data Isolation](vulnerabilities/v4-disabled-data-isolation/reference.md)
- [V5 — Missing Input Validation](vulnerabilities/v5-missing-input-validation/reference.md)
- [V6 — Baking Secrets into Source](vulnerabilities/v6-baking-secrets/reference.md)
- [V7 — AI Default Credentials](vulnerabilities/v7-ai-default-credentials/reference.md)
- [V8 — Flawed Object Authorization](vulnerabilities/v8-flawed-object-authorization/reference.md)
- [V9 — Denial of Wallet & Rate-Limiting](vulnerabilities/v9-denial-of-wallet/reference.md)
- [V10 — CORS & IAM Perimeter Dissolution](vulnerabilities/v10-cors-iam-perimeter/reference.md)
- [V11 — Structural Type Enforcement](vulnerabilities/v11-structural-type-enforcement/reference.md)

## Great References

https://www.sherlockforensics.com/blog/security-prompts-every-vibe-coder-needs.html

https://snehbavarva.medium.com/secure-vibe-coding-in-2026-the-files-prompts-and-rules-of-use-and-research-e821021ee908

[https://catdoes.com/blog/vibe-coding-security-checklist](https://catdoes.com/blog/vibe-coding-security-checklist)