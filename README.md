# 🛡️ THADAM — The Intelligent Cyber-Fraud Investigation Companion

**Problem Statement:** PS01 · Cyber Fraud / Phishing / Malicious Apps  
**Title:** Scam Message & Phishing Link Detection with Fake Loan / Investment App and Fraudulent Website Analysis[cite: 8]  
**Event:** Rajasthan Police Cyber Security Hackathon 2026 (R4C)[cite: 8, 9]  
**Team:** DYNAMITE[cite: 8]

---

## 📋 Problem Statement

Citizens routinely receive fraudulent KYC, parcel, electricity-bill, and job messages containing malicious links. Simultaneously, fake instant-loan and investment Android apps misuse sensitive user permissions, while Ponzi, MLM, and illegal betting websites lure victims with unrealistic guaranteed returns[cite: 1]. Although these fraud operations frequently reuse the same domains, app identifiers, phone numbers, and UPI/bank/crypto payment accounts across channels, they are reported and investigated in isolation[cite: 1].

**Objective:** Build a unified cyber-fraud investigation platform that ingests suspicious messages, URLs, Android APKs/app-store links, and websites; analyzes their content and technical indicators; extracts actionable identifiers; links cross-channel fraud campaigns with explainable **Low / Medium / High** risk verdicts; and maintains searchable case records, heat-lists, and downloadable evidence reports for police investigation[cite: 1].

---

## 💡 Our Solution — THADAM

**THADAM** (_The Intelligent Cyber-Fraud Investigation Companion_) is an AI-powered, multilingual digital forensics and cyber-fraud attribution platform built for R4C investigators and citizens[cite: 9].

### What Makes THADAM Different

- **Unified Multi-Artifact Intake:** Analyzes SMS/WhatsApp/email text, phishing URLs, fraudulent Ponzi/betting websites, Android APKs, and screenshots/QR codes in a single workspace[cite: 9, 10].
- **Dialect-Aware Multilingual Intelligence:** Detects scam intent, urgency lures, and brand impersonation across English, Hindi, and 6 regional Rajasthani dialects (_Marwari, Mewari, Dhundhari, Hadoti, Mewati, Bagri_)[cite: 9, 12].
- **Static-Only APK & Website Forensics:** Safely inspects `AndroidManifest.xml` permissions (`READ_SMS`, `RECEIVE_SMS`, `SYSTEM_ALERT_WINDOW`), `.dex` bytecode URLs, and website payment trails without risky sandbox execution[cite: 10, 11].
- **Automated Identifier Extraction & Cross-Channel Linking:** Automatically extracts UPI VPAs, `+91` phone numbers, domains, crypto wallets, and SHA-256 hashes, then correlates separate cases sharing identical infrastructure into syndicate clusters[cite: 9, 10].
- **Explainable Risk Scoring & Dossier Generation:** Assigns transparent **Low / Medium / High** risk tiers backed by exact triggered signals and generates investigation-ready PDF/Markdown dossiers[cite: 9, 10].

---

## 🏗️ System Architecture

```mermaid
flowchart TB
    %% Professional Color Palette
    classDef userNode fill:#071936,stroke:#1d4ed8,stroke-width:2px,color:#ffffff,font-weight:bold
    classDef inputNode fill:#eff6ff,stroke:#2563eb,stroke-width:1.5px,color:#0f172a
    classDef orchNode fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#ffffff,font-weight:bold
    classDef engineNode fill:#ffffff,stroke:#0284c7,stroke-width:1.5px,color:#0f172a
    classDef controlNode fill:#fffbeb,stroke:#d97706,stroke-width:1.5px,color:#0f172a
    classDef memoryNode fill:#ecfdf5,stroke:#059669,stroke-width:1.5px,color:#0f172a
    classDef outputNode fill:#fef2f2,stroke:#dc2626,stroke-width:1.5px,color:#0f172a

    subgraph L1["1️⃣ USERS & MULTIMODAL EVIDENCE INTAKE"]
        direction LR
        U["👮 Investigator • Analyst • Citizen"]:::userNode
        I1["📩 Messages<br/>SMS • WhatsApp • Email"]:::inputNode
        I2["🌐 URLs & Websites<br/>Phishing • Ponzi • Betting"]:::inputNode
        I3["📱 Android APKs<br/>Fake Loan & Trading Apps"]:::inputNode
        I4["🖼️ Media & Docs<br/>Screenshots • QR • PDFs"]:::inputNode
        U --> I1 & I2 & I3 & I4
    end

    subgraph L2["2️⃣ INTELLIGENT ANALYSIS ORCHESTRATOR"]
        direction LR
        O1["🔍 Artifact Detection<br/>& Smart Routing"]:::orchNode
        O2["⚡ Parallel Static &<br/>NLP Execution"]:::orchNode
        O3["🧩 Evidence Consolidation<br/>& Provenance Tagging"]:::orchNode
        O1 --> O2 --> O3
    end

    subgraph L3["3️⃣ SPECIALIST FORENSIC ANALYSERS"]
        direction LR
        E1["🗣️ Multilingual & Dialect NLP<br/>• 6 Rajasthani Dialects + Hindi/EN<br/>• Urgency & Fake KYC Lures<br/>• Brand Impersonation"]:::engineNode
        E2["🔗 URL & Domain Scanner<br/>• Look-Alike & Risky TLD Check<br/>• HTTPS & Redirect Audit<br/>• Threat Intel Lookup"]:::engineNode
        E3["🕸️ Isolated Website Forensics<br/>• Ponzi / MLM / ROI Detection<br/>• UPI / Bank / Crypto Scrape<br/>• Safe Content Fingerprinting"]:::engineNode
        E4["🛡️ Static-Only APK Inspector<br/>• Manifest Permission Audit<br/>• SHA-256 & Package Metadata<br/>• Embedded C2 URL Extraction"]:::engineNode
        E5["📷 Media OCR & QR Decoder<br/>• Screenshot Text Extraction<br/>• Malicious QR Decoding<br/>• Logo & Payment Capture"]:::engineNode
    end

    subgraph L4["4️⃣ DECISION, CORRELATION & GOVERNANCE LAYER"]
        direction LR
        C1["🎯 Explainable Risk Engine<br/>Low / Medium / High + Reasons"]:::controlNode
        C2["🧬 Cross-Channel Syndicate Matcher<br/>UPI • Phone • Domain • Hash Pivots"]:::controlNode
        C3["🕒 Temporal Audit & Review<br/>Human-in-the-Loop Verification"]:::controlNode
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
        D1["🖥️ Live Scanner & Gauge"]:::outputNode
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
```
