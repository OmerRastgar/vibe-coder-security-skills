# V4 — Disabled Data Isolation

Cross-tenant data leaks and the failure to enforce proper data boundaries. Policies are missing or disabled across relational DBs (missing RLS), NoSQL layers (shared keyspaces), Vector/Graph databases, and BaaS platforms (wildcard client rules).

Targets: RDBMS, NoSQL/Document & Key-Value, Vector & Graph AI Layer, BaaS & Cloud Layers.

---

## Attack Surface Flowchart

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

---

[<-- Back to full guide: Readme.md](../../Readme.md)
