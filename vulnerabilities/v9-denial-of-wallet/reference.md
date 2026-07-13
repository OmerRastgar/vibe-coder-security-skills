# V9 — Denial of Wallet & Rate-Limiting

Financial and resource exhaustion by leveraging unmetered boundaries. Attackers hit costly AI endpoints without user quotas, run blocking synchronous loops for compute-heavy tasks, trigger cloud-autoscaling bloat, and perform credential stuffing or SMS pumping on unrestricted auth endpoints.

Targets: costly AI endpoints, high-compute tasks, auth portal abuse, unbounded searches.

---

## Attack Surface Flowchart

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
