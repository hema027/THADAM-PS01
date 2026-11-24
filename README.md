# 🛡️ THADAM — The Intelligent Cyber-Fraud Investigation Companion

**Problem Statement:** PS01 · Cyber Fraud / Phishing / Malicious Apps  
**Title:** Scam Message & Phishing Link Detection with Fake Loan / Investment App and Fraudulent Website Analysis  
**Event:** Rajasthan Police Cyber Security Hackathon 2026 (R4C)  
**Team:** DYNAMITE  

---

## 📋 Problem Statement (5 Key Challenges)

1. **Multi-Channel Scam Proliferation:** Citizens are continuously targeted via fraudulent KYC, parcel delivery, electricity-bill, and job-offer messages carrying malicious phishing links across SMS, WhatsApp, and email.
2. **Predatory Fake Loan & Investment Apps:** Malicious Android APKs masquerading as instant-loan or high-return trading platforms misuse sensitive permissions (contacts, SMS, call logs, screen overlays) to extort and defraud victims.
3. **Deceptive Ponzi, MLM & Betting Websites:** Fraudulent web portals lure users with unrealistic guaranteed ROI schemes, fake regulatory badges, and rigged betting interfaces.
4. **Siloed & Fragmented Investigations:** Although scam campaigns routinely reuse identical domains, app signing metadata, phone numbers, and UPI/bank/crypto accounts across channels, individual complaints are analyzed in isolation.
5. **Lack of Explainable, Court-Ready Evidence:** Investigators lack a unified triage tool that produces transparent **Low / Medium / High** risk verdicts alongside structured, actionable dossiers for rapid takedown and bank/UPI freeze requests.

---

## 💡 Our Solution — THADAM (5 Core Pillars)

1. **Unified Multimodal Artifact Intake:** Ingests suspicious SMS/WhatsApp/email text, phishing URLs, fraudulent websites, Android APKs, and screenshots/QR codes inside a single investigator console.
2. **Dialect-Aware Multilingual Scam NLP:** Detects social-engineering urgency lures, fake KYC/bill traps, and brand impersonation across English, Hindi, and 6 regional Rajasthani dialects (*Marwari, Mewari, Dhundhari, Hadoti, Mewati, Bagri*).
3. **Safe Static-Only APK & Website Forensics:** Decompiles `AndroidManifest.xml` permissions and `.dex` bytecode strings while inspecting website DOM/payment trails in isolation—eliminating live malware execution risks.
4. **Automated Identifier Extraction & Syndicate Correlation:** Automatically extracts UPI VPAs, `+91` phone numbers, look-alike domains, crypto wallets, and SHA-256 hashes, linking separate complaints that share infrastructure into unified syndicate campaigns.
5. **Explainable Risk Scoring & One-Click Police Dossiers:** Computes transparent **Low / Medium / High** risk tiers backed by human-readable trigger reasons and exports investigation-ready PDF and Markdown evidence reports.

---

## 🌟 Novelty & Unique Selling Propositions (5 USPs)

1. **Rajasthani Dialect & Code-Mixed Scam Intelligence:** Unlike generic English-only phishing filters, THADAM natively understands regional Rajasthani dialects and Hinglish coercion patterns used in localized rural and urban cyber frauds.
2. **Cross-Channel Syndicate Graph Attribution:** Connects seemingly unrelated SMS lures, fake websites, and sideloaded APKs through shared payment trails (UPI/bank/crypto) and infrastructure pivots to expose the master syndicate behind multiple cases.
3. **Zero-Execution Static Binary & Web Forensics:** Extracts embedded Command-and-Control (C2) endpoints, dangerous permission combinations, and payment handles statically in seconds without requiring heavy dynamic sandboxes.
4. **Glass-Box Explainable Forensics for Law Enforcement:** Every risk score is paired with exact indicator provenance, feature weights, and rule justifications so investigators can defend findings in legal and banking freeze proceedings.
5. **Instant Actionable Takedown & Freeze Readiness:** Bridges the gap between detection and enforcement by auto-formatting extracted indicators into ready-to-dispatch PDF/Markdown dossiers and live threat heat-lists.

---

## 🏗️ System Architecture

```mermaid
flowchart TB
    %% Institutional Blue & High-Contrast Palette
    classDef userNode fill:#071936,stroke:#1d4ed8,stroke-width:2px,color:#ffffff,font-weight:bold
    classDef inputNode fill:#eff6ff,stroke:#2563eb,stroke-width:1.5px,color:#0f172a
    classDef orchNode fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#ffffff,font-weight:bold
    classDef engineNode fill:#ffffff,stroke:#0284c7,stroke-width:1.5px,color:#0f172a
    classDef controlNode fill:#fffbeb,stroke:#d97706,stroke-width:1.5px,color:#0f172a
    classDef memoryNode fill:#ecfdf5,stroke:#059669,stroke-width:1.5px,color:#0f172a
    classDef outputNode fill:#fef2f2,stroke:#dc2626,stroke-width:1.5px,color:#0f172a

    subgraph L1["1️⃣ USERS & MULTIMODAL EVIDENCE INTAKE"]
        direction LR
        U["👮 R4C Investigator • Analyst • Citizen"]:::userNode
        I1["📩 Scam Messages<br/>SMS • WhatsApp • Email"]:::inputNode
        I2["🌐 URLs & Websites<br/>Phishing • Ponzi • Betting"]:::inputNode
        I3["📱 Android APKs<br/>Fake Loan & Investment Apps"]:::inputNode
        I4["🖼️ Media & Docs<br/>Screenshots • QR • PDFs"]:::inputNode
        U --> I1 & I2 & I3 & I4
    end

    subgraph L2["2️⃣ INTELLIGENT ANALYSIS ORCHESTRATOR"]
        direction LR
        O1["🔍 Artifact Classification<br/>& Smart Routing"]:::orchNode
        O2["⚡ Parallel Static &<br/>NLP Pipeline"]:::orchNode
        O3["🧩 Indicator Normalization<br/>& Provenance Tagging"]:::orchNode
        O1 --> O2 --> O3
    end

    subgraph L3["3️⃣ SPECIALIST FORENSIC ENGINES"]
        direction LR
        E1["🗣️ Multilingual & Dialect NLP<br/>• 6 Rajasthani Dialects + HI/EN<br/>• Urgency & Fake KYC Lures<br/>• Brand Impersonation"]:::engineNode
        E2["🔗 URL & Domain Scanner<br/>• Look-Alike & Punycode Check<br/>• Risky TLD & Redirect Audit<br/>• Threat Intel Lookup"]:::engineNode
        E3["🕸️ Isolated Website Forensics<br/>• Ponzi / MLM / ROI Detection<br/>• UPI / Bank / Crypto Scrape<br/>• Safe Content Fingerprinting"]:::engineNode
        E4["🛡️ Static-Only APK Inspector<br/>• Manifest Permission Audit<br/>• SHA-256 & Package Metadata<br/>• Embedded C2 URL Extraction"]:::engineNode
        E5["📷 Media OCR & QR Decoder<br/>• Screenshot Text Extraction<br/>• Malicious QR Decoding<br/>• Payment Handle Capture"]:::engineNode
    end

    subgraph L4["4️⃣ DECISION, CORRELATION & GOVERNANCE LAYER"]
        direction LR
        C1["🎯 Explainable Risk Engine<br/>Low / Medium / High + Reasons"]:::controlNode
        C2["🧬 Cross-Channel Syndicate Matcher<br/>UPI • Phone • Domain • Hash Pivots"]:::controlNode
        C3["🕒 Human-in-the-Loop Governance<br/>Audit Trail & Analyst Review"]:::controlNode
    end

    subgraph L5["5️⃣ UNIFIED INTELLIGENCE MEMORY (SQLite + Knowledge Graph)"]
        direction LR
        M1["📁 Case & Observation Store"]:::memoryNode
        M2["🔎 Indicator Intelligence Index"]:::memoryNode
        M3["🕸️ Syndicate Knowledge Graph"]:::memoryNode
        M4["📜 Timeline & Audit History"]:::memoryNode
    end

    subgraph L6["6️⃣ R4C COMMAND DASHBOARD & ACTIONABLE OUTPUTS"]
        direction LR
        D1["🖥️ Live Scanner & Risk Gauge"]:::outputNode
        D2["📋 Searchable Case Queue"]:::outputNode
        D3["🌐 Interactive Syndicate Graph"]:::outputNode
        D4["📄 PDF / MD Police Dossier"]:::outputNode
        D5["🔥 Trending Threat Heat-List"]:::outputNode
    end

    I1 & I2 & I3 & I4 --> O1
    O2 --> E1 & E2 & E3 & E4 & E5
    E1 & E2 & E3 & E4 & E5 --> O3
    O3 --> C1 & C2 & C3
    C1 & C2 & C3 <--> M1 & M2 & M3 & M4
    M1 & M2 & M3 & M4 --> D1 & D2 & D3 & D4 & D5
