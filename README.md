---
license: apache-2.0
---
# 🛡️ Energy-Guard OS: Sovereign AI Security Gateway



> **The world's first on-premise AI security gateway delivering real-time protection for Large Language Models (LLMs) with performance that far surpasses cloud and traditional solutions.**

Energy-Guard OS is a CPU-native, sovereign AI security gateway that protects enterprise LLM deployments in real time. Operating at **under 13 milliseconds per request without a GPU**, fitting entirely within **411 MB**, and processing over **9,500 words per second**, it occupies a category that no competitor currently addresses: lightweight, sovereign, and comprehensively intelligent AI security.

---

##  Key Capabilities and Features

###  Ultra-Fast Performance
- **Internal kernel latency: 4.1 to 13 milliseconds**
- Single-request mode: ~13ms processing time
- Batch processing mode: ~4.1ms per request (at 100-250 batch size)
- Real-world API throughput: **427.77 requests/second**
- The system becomes **more efficient under load** through full tensor utilization

###  Minimal System Footprint
- **Entire system operates at only 411 MB**
- Smallest known intelligent security gateway
- CPU-only operation — no GPU required
- No Kubernetes orchestration needed
- Zero external dependencies

###  Complete Sovereignty (Air-Gapped)
- **No GPU or cloud connection required**
- Fully compliant with GDPR, EU AI Act, HIPAA, and SOX
- All processing occurs in RAM — zero disk writes of content
- Perfect for government, defense, and regulated industries
- Deploy on any bare-metal fleet without routing data through third-party clouds

###  Comprehensive Threat Coverage
Energy-Guard OS is **the only system** that integrates threat intelligence for **IT, AI, and OT/SCADA** into a single processing line:

| Category | Frameworks | Coverage |
|----------|------------|----------|
| **AI Threats** | MITRE ATLAS | Model extraction, adversarial inputs, supply chain poisoning |
| **IT Threats** | MITRE ATT&CK | APT groups, lateral movement, Kerberoasting, pass-the-hash |
| **LLM Security** | OWASP LLM Top 10 | Prompt injection, insecure output, sensitive disclosure, XSS |
| **OT/SCADA** | Triton, Stuxnet, PIPEDREAM | Modbus/DNP3/Triconex patterns in AI conversations |
| **Evasion** | 8-Layer Decoding | Base64, URL, HTML, Hex, ROT13, Zero-width, Unicode, Double-encode |
| **Multilingual** | Arabic RTL + Unicode | Full semantic Arabic detection; Chinese, Russian, German support |

###  Full Arabic Language Support
- Deep semantic processing of right-to-left (RTL) text
- Full Arabic attack detection at inference level
- Not surface-level filtering — true semantic understanding

###  Session Intelligence
- **Cumulative threat scoring** across entire conversation sessions
- Multi-turn escalation detection
- Per-user risk accumulation with exponential decay
- Role-based adaptive thresholds
- Detects social engineering attacks spanning multiple conversation turns

---

##  Benchmarks

### Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| **Capacity** | 9,541 words/second | 7.5× above industry benchmark |
| **Single Request Latency** | 13 ms | Kernel processing time |
| **Batch Latency** | 4.1 ms/request | At 100-250 batch size |
| **Real-World RPS** | 427.77 req/sec | Live endpoint under load |
| **Peak Throughput** | 345 req/sec | Kernel stress test |
| **Stress Test** | 0 dropped batches | 2,500 requests, 10 threads |
| **System Footprint** | 411 MB | CPU-only, no GPU |

### Detection Accuracy

| Attack Category | Accuracy | Status |
|-----------------|----------|--------|
| **Financial Data Leaks** (IBAN, SWIFT, wire transfers) | **100%** | Production Ready |
| **PII/Private Data** (SSN, passport, API keys, credentials) | **100%** | Production Ready |
| **Strategic Leaks** (M&A documents, roadmaps) | **100%** | Production Ready |
| **Technical Code** (malware, injection) | 72.8% | Active Improvement |

### Independent Security Benchmark (JailbreakBench)

| System | F1-Score | Attack Success Rate ↓ | AUROC |
|--------|----------|----------------------|-------|
| **Energy-Guard OS** | **0.722** | **0.292** | **0.651** |
| LlamaGuard-2 | 0.529 | 0.640 | 0.680 |
| Keyword Filter | 0.246 | 0.860 | 0.570 |

---

##  Architecture: Three-Path Sovereign Decision Engine

Every input passes through three analytical paths in sequence. The first path to reach a definitive conclusion terminates the pipeline — enabling sub-13ms total latency without sacrificing coverage depth.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENERGY-GUARD OS V27                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │  Path ①      │   │  Path ②      │   │  Path ③          │   │
│  │  Sovereign   │──▶│  Rule Engine │──▶│  Neural Engine   │   │
│  │  Energy Map  │   │  (600+ regex)│   │  (15.4M params)  │   │
│  │  < 1ms       │   │  < 2ms       │   │  4-13ms          │   │
│  └──────────────┘   └──────────────┘   └──────────────────┘   │
│         │                  │                    │               │
│         ▼                  ▼                    ▼               │
│  Known signatures    Deterministic threats   Novel & semantic   │
│  Safe-category       8-layer decode          Adaptive scoring   │
│  fast-pass           pre-scan                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 8-Layer Evasion Decoding Engine

Before any security analysis, every input is recursively decoded through 8 layers:

| Layer | Encoding Defeated | Example |
|-------|-------------------|---------|
| 1 | Base64 (Standard + URL-safe) | `aWdub3Jl...` → "ignore all previous instructions" |
| 2 | URL Percent Encoding | `%69%67%6e...` → "ignore" |
| 3 | HTML Entities | `&#105;&#103;...` → "ignore" |
| 4 | Hex Escape Sequences | `\x69\x67...` → "ignore" |
| 5 | ROT13 Cipher | `vtzber nyy...` → "ignore all..." |
| 6 | Zero-Width Characters | `i​g​n​o​r​e` (hidden chars stripped) |
| 7 | Unicode Normalization | `ｉｇｎｏｒｅ` / Cyrillic homoglyphs → "ignore" |
| 8 | Double-Encoding | `%2569%6e...` decoded twice → plain text |

> ⚠️ **Key Differentiator:** Without multi-layer recursive decoding, a single Base64 wrapper bypasses 100% of pattern-matching defenses in competing products.

---

##  Testing Tools

This repository includes official testing tools to independently verify all performance and security claims:

### Tool A: Sovereign Master Test Suite (v10.2)

```bash
# File: EnergyGuard_OS_Sovereign_Master_Test_Suite_v10.2.py
```

| Property | Value |
|----------|-------|
| **Test Volume** | 10,000+ test cases |
| **Coverage** | OWASP LLM Top 10, MITRE ATLAS, MITRE ATT&CK |
| **Performance Mode** | AsyncIO pipeline — 1,000+ cases/second |
| **Stress Testing** | Up to 1,000 concurrent users |
| **Language Coverage** | Arabic + English attack vectors |
| **Output** | JSON report + per-category accuracy + latency histogram |

**What it validates:**
- Detection accuracy across all 8 attack taxonomy categories
- System stability under maximum concurrent load
- Sub-13ms latency validation across all test conditions
- Arabic vs. English detection parity

### Tool B: EBMSovereign Independent Security Benchmark

```bash
# File: EBMSovereign_Independent_Security_Benchmark.py
```

| Property | Value |
|----------|-------|
| **Datasets** | JailbreakBench + HarmBench + Alpaca (public, reproducible) |
| **Detection Method** | Dual-signal: verdict string + risk_score threshold |
| **Metrics** | ASR, F1-Score, Precision, Recall, AUROC, FPR |
| **Baseline Comparison** | vs. LlamaGuard-2 proxy and keyword filter |
| **Output** | `benchmark_results.json` + `benchmark_report.txt` + 6 PNG figures |

**What it validates:**
- Attack Success Rate against 500 real-world jailbreak prompts
- False Positive Rate against 500 benign prompts
- API latency distribution (P50, P95, P99)
- Statistical significance via Mann-Whitney U test

### Running the Evaluation Tools

```bash
# Prerequisites
pip install aiohttp datasets scikit-learn matplotlib seaborn numpy tqdm scipy

# Configure API endpoint
BASE_URL = 'http://ebmsovereign.com/v1/process'

# Run Sovereign Master Test Suite
python EnergyGuard_OS_Sovereign_Master_Test_Suite_v10.2.py

# Run Independent Security Benchmark
python EBMSovereign_Independent_Security_Benchmark.py
```

---

##  Public API Reference

Test the system directly via the live endpoint (no registration required for initial testing):

| Property | Value |
|----------|-------|
| **Base URL** | `http://ebmsovereign.com/v1/` |
| **Authentication** | `X-API-Key` header (contact for production key) |
| **Response Format** | JSON with verdict, risk_score, and performance metadata |
| **Uptime SLA** | 99.9% under enterprise partnership |

### Endpoint 1: Single Request Analysis

```http
POST /v1/process
Content-Type: application/json
```

**Request:**
```json
{
  "text": "Your prompt or LLM response to inspect",
  "uid": "user_session_id_optional"
}
```

**Response:**
```json
{
  "verdict": "✅ SAFE",
  "risk_score": 0.1234,
  "label": "unknown",
  "processing_time_ms": 12.87,
  "uid": "user_session_id_optional",
  "timestamp": 1775416327.208
}
```

**Response Fields:**

| Field | Type | Range | Interpretation |
|-------|------|-------|----------------|
| `verdict` | string | "✅ SAFE" or "🚨 BLOCKED" | Primary binary decision |
| `risk_score` | float | 0.0 – 1.0 | < 0.50: safe \| 0.50–0.85: borderline \| > 0.85: block |
| `processing_time_ms` | float | 0.39 – 15.0 ms | Internal engine time only |
| `label` | string | threat type or 'unknown' | Threat category for logging |
| `uid` | string | Echo of request uid | For request correlation |

### Endpoint 2: Batch Processing

```http
POST /v1/process_batch
Content-Type: application/json
```

**Request:**
```json
{
  "queries": [
    { "uid": "req_001", "text": "First text to inspect" },
    { "uid": "req_002", "text": "Second text to inspect" },
    ... up to 250 items per batch
  ]
}
```

**Response:**
```json
{
  "results": [
    {
      "uid": "req_001",
      "verdict": "✅ SAFE",
      "risk_score": 0.1234,
      "label": "unknown"
    }
  ],
  "performance": {
    "batch_size": 250,
    "total_time_ms": 1040.12,
    "avg_latency_ms": 4.16,
    "throughput_rps": 240.35
  }
}
```

### Risk Score Decision Logic (V27 Parser)

Implement this dual-signal logic to minimize false negatives:

```python
def parse_v27_response(body: dict) -> tuple[bool, float]:
    """
    Parse Energy-Guard OS V27 response.
    Returns: (is_blocked: bool, risk_score: float)
    """
    verdict = str(body.get('verdict', '')).upper()
    risk_score = float(body.get('risk_score', 0.0))
    
    # Signal 1: explicit verdict string
    if 'BLOCKED' in verdict or 'WARNING' in verdict:
        return True, risk_score  # is_blocked = True
    
    # Signal 2: risk score threshold fallback
    if 'SAFE' in verdict and risk_score <= 0.85:
        return False, risk_score  # is_blocked = False
    
    # Fallback: score-only decision
    return risk_score > 0.85, risk_score
```

### HTTP Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 OK | Request processed successfully | Read verdict and risk_score |
| 422 | Validation error in payload | Ensure 'queries' array with 'uid' and 'text' |
| 429 | Rate limit exceeded | Implement exponential backoff |
| 500 | Kernel processing error | Retry once; report if persistent |
| 504 | Gateway timeout | Reduce batch size to 100–150 |

---

##  Competitive Comparison

| System | Deployment | CPU Latency | Size | GPU Required | On-Premise | ICS/SCADA | Arabic |
|--------|------------|-------------|------|--------------|------------|-----------|--------|
| Azure Prompt Shield | SaaS Only | ~349 ms | Cloud | Yes | ❌ | ❌ | ❌ |
| AWS Bedrock Guardrails | SaaS Only | ~200+ ms | Cloud | Yes | ❌ | ❌ | ❌ |
| Lakera Guard | SaaS/Hosted | ~61 ms | Unknown | Optional | Partial | ❌ | ❌ |
| LlamaGuard-86M | Self-hosted | ~304 ms | Large | Yes | ✅ | ❌ | ❌ |
| NeuralTrust-118M | Self-hosted | ~39 ms | Large | Optional | ✅ | ❌ | ❌ |
| CalypsoAI | Enterprise | ~250 ms | Large | Yes | ✅ | ❌ | ❌ |
| **Energy-Guard OS** | **Air-gapped/Any** | **4.1–13 ms** | **411 MB** | **No** | **✅** | **✅** | **✅** |

---

##  Use Cases

### Deployment Patterns

| Pattern | Description | Best For |
|---------|-------------|----------|
| **Inline API Proxy** | Energy-Guard sits in front of OpenAI, Claude, Gemini | SaaS hosting, multi-tenant AI platforms |
| **Edge Sidecar** | Deployed alongside customer's LLM as container | Dedicated servers, private cloud, K8s |
| **Air-Gapped Gateway** | Fully isolated, no external dependencies | Government, defense, regulated industries |
| **Marketplace Add-On** | One-click activation from control panel | Self-serve cloud providers |

### Target Segments

| Segment | Key Pain Point | Energy-Guard Value |
|---------|----------------|-------------------|
| **Banking & Finance** | Regulatory exposure (SOX, GDPR) | 100% financial leak detection; air-gapped |
| **Healthcare** | HIPAA compliance | PII/PHI filtering; on-premise; audit trail |
| **Government & Defense** | Classified data sovereignty | Air-gapped; Arabic + multilingual; ICS-aware |
| **Energy & Utilities** | OT/SCADA AI-enabled | Only product with native ICS/SCADA patterns |
| **SaaS/AI Builders** | Customer data protection | $0.001/req; 427 RPS; zero infrastructure |

---

##  Partnership Opportunities

| Partnership Tier | Model | Revenue Structure |
|------------------|-------|-------------------|
| **Technology OEM** | Embed engine in your platform | Negotiated royalty per activation |
| **Marketplace Reseller** | One-click add-on in marketplace | 30–40% margin |
| **White-Label Partner** | Deploy under your brand | 40–50% margin |
| **Referral Partner** | Refer enterprise customers | 20% commission |

---

##  Contact & Support

- **Website:** [ebmsovereign.com](https://ebmsovereign.com)
- **Email:** arrangements@ebmsovereign.com
- **Live API:** `http://ebmsovereign.com/v1/`
- **Partnership:** arrangements@ebmsovereign.com

---

##  License

Energy-Guard OS is commercial software. Contact EBMSovereign for licensing terms.

---

<p align="center">
  <strong>EBMSovereign · Sovereign AI Security</strong><br>
  <em>CPU-native. 411 MB. 4.1–13ms. Air-gapped. Covers IT + AI + OT/SCADA. Speaks Arabic.</em>
</p>
