# V3 — Client-Side Security Misplacements

Applications that misplace their trust in frontend client logic rather than backend enforcement. Route guards, feature flags, checkout math, or unverified JWT claims can be bypassed directly by manipulating the browser environment.

Targets: Auth & access navigation, forms & inputs, data flow & math.

---

## Attack Surface Flowchart

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

---

[<-- Back to full guide: Readme.md](../../Readme.md)
