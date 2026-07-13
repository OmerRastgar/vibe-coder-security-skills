# V2 — Package Hallucination

A unique AI-era vulnerability where LLMs "hallucinate" non-existent software packages. Malicious actors scan for these common hallucinations and squat on those names in package registries. If a developer uses the AI's hallucinated code, their manifests and lockfiles pull down malicious payloads.

Targets: dependency manifests, lockfiles, CI/CD & infra, source code imports.

---

## Attack Surface Flowchart

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
