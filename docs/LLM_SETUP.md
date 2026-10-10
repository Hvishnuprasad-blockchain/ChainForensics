# ChainForensics v2: LLM Recovery Recommendation Setup Guide

## 1. Overview & Architecture

ChainForensics v2 introduces an AI-powered, contextual recovery recommendation engine layered on top of the v1 deterministic rule-based engine. 

It is implemented using the **Strategy / Adapter Pattern**:
- **Interface:** `RecoveryRecommendationProvider` (`chainforensics/recovery/provider.py`)
- **Deterministic Implementation:** `RuleBasedRecoveryProvider` (v1 rule-based baseline, execution latency `<1ms`, 100% offline guarantee).
- **Adaptive LLM Implementation:** `LlmRecoveryProvider` (`chainforensics/recovery/llm_provider.py`) supporting both Groq Cloud (hosted free tier) and Ollama (local offline).

### Fail-Safe Fallback Guarantee
In default mode (`RECOVERY_ENGINE=llm_with_fallback`):
- The system attempts an LLM call with a strict **2.5s timeout**.
- If any failure occurs (missing API key, network timeout, rate limit, or malformed JSON), it **automatically falls back** to the untouched v1 rule-based engine and logs the fallback event.
- An incident is **never** left unanalyzed.

---

## 2. Option 2 Setup: Free Hosted Groq Cloud (Recommended)

Groq Cloud offers a genuinely free tier with **zero credit card commitment**, providing sub-second inference (~300 tokens/sec) on `llama-3.1-8b-instant`.

### Step-by-Step Instructions:

1. **Create Free Account:**
   Navigate to [https://console.groq.com/keys](https://console.groq.com/keys) and sign in using Google, GitHub, or email.

2. **Generate API Key:**
   - Click the **"Create API Key"** button.
   - Enter a name (e.g., `chainforensics-v2`).
   - Copy the generated API key (it starts with `gsk_...`).

3. **Configure Environment:**
   Open `.env` in the root of the project and add:
   ```bash
   RECOVERY_ENGINE=llm_with_fallback
   LLM_PROVIDER=groq
   GROQ_API_KEY=gsk_your_actual_key_here
   GROQ_MODEL=llama-3.1-8b-instant
   LLM_TIMEOUT_SECONDS=2.5
   ```

4. **Verify Live Output:**
   Run an incident detection via API or the v2 SOC Dashboard (`http://localhost:8000/dashboard/v2/`). The incident replay view will display contextual recommendations enriched with telemetry details.

---

## 3. Option 1 Setup: Free Local Ollama (Offline Alternative)

If you prefer 100% offline, zero-data-leakage execution:

1. Download and install Ollama from [https://ollama.com](https://ollama.com).
2. Open your terminal and pull a lightweight model:
   ```bash
   ollama run llama3.2:1b
   ```
3. Set your `.env`:
   ```bash
   RECOVERY_ENGINE=llm_with_fallback
   LLM_PROVIDER=ollama
   OLLAMA_BASE_URL=http://localhost:11434/v1
   OLLAMA_MODEL=llama3.2:1b
   LLM_TIMEOUT_SECONDS=3.0
   ```

---

## 4. Configuration Reference

| Environment Variable | Allowed Values | Default | Description |
| :--- | :--- | :--- | :--- |
| `RECOVERY_ENGINE` | `llm_with_fallback`, `llm`, `rule_based` | `llm_with_fallback` | Controls recovery engine mode. |
| `LLM_PROVIDER` | `groq`, `ollama` | `groq` | Underlying LLM provider adapter. |
| `GROQ_API_KEY` | string (`gsk_...`) | `""` | Groq Cloud free-tier API key. |
| `GROQ_MODEL` | string | `llama-3.1-8b-instant` | Model identifier on Groq Cloud. |
| `OLLAMA_BASE_URL` | URL | `http://localhost:11434/v1` | Local Ollama endpoint. |
| `LLM_TIMEOUT_SECONDS` | float | `2.5` | Max duration before fallback activates. |
