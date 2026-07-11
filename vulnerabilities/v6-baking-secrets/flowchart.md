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
