# BugLens — LLM-Based Bug Detection Tool

**Author:** Aashik Poudel  
**Institution:** Lappeenranta–Lahti University of Technology (LUT University), 2026  
**Thesis:** Automated Testing: Bug Identification Using Large Language Models  

---

## Overview

BugLens is a web-based bug detection tool that uses a research-grade Large Language Model pipeline to automatically identify security vulnerabilities and bugs in source code. It supports 12 programming languages and produces structured bug reports with CWE classification, confidence scores, and weighted severity scoring.

---

## Pipeline (6 Stages)

1. **Code Embedding** — Source code is converted to a 1536-dimensional vector using OpenAI text-embedding-3-small
2. **CWE Vector Retrieval** — Top-3 most semantically similar entries are retrieved from a local CWE Top 25 knowledge base using cosine similarity
3. **Few-Shot RAG Prompt Construction** — Retrieved CWE entries are injected into the prompt as few-shot examples
4. **Multi-Run LLM Analysis** — GPT-4o-mini is called N=5 times independently (temperature=0.7)
5. **Self-Consistency Voting** — Only bugs appearing in k≥3 of 5 runs are confirmed. Confidence = confirmed_runs / total_runs
6. **Severity Scoring** — Risk Score = (High×3) + (Medium×2) + (Low×1)

---

## Features

- Supports Python, JavaScript, Java, C, C++, TypeScript, PHP, Go, Ruby, Rust, Swift, Kotlin
- CWE Top 25 knowledge base with 25 vulnerability entries
- Self-consistency voting reduces hallucinations
- Confidence scores on every confirmed bug
- Weighted risk score with risk level classification
- Clean web interface with severity filtering
- REST API backend with health check endpoint

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python + Flask |
| LLM | GPT-4o-mini (OpenAI API) |
| Embeddings | text-embedding-3-small |
| Vector Index | NumPy (in-memory cosine similarity) |
| Frontend | HTML + CSS + JavaScript |

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/Code-Aashik/BugLens.git
cd BugLens
```

### 2. Install dependencies
```bash
pip install flask requests numpy
```

### 3. Set your OpenAI API key
```bash
# Windows PowerShell
$env:OPENAI_API_KEY="sk-your-key-here"
```

### 4. Run the application
```bash
python app.py
```

### 5. Open in browser
http://localhost:5000

---

## Project Structure
BugLens/

├── app.py                  # Flask backend + full 6-stage pipeline

├── cwe_knowledge_base.py   # CWE Top 25 knowledge base (25 entries)

├── requirements.txt        # Dependencies

├── templates/

│   └── index.html          # Frontend HTML

└── static/

├── style.css           # Stylesheet

└── main.js             # Frontend JavaScript

---

## How It Works

1. User pastes source code into the web editor and selects a language
2. The backend embeds the code using OpenAI embeddings
3. The 3 most similar CWE vulnerability types are retrieved from the knowledge base
4. A structured prompt is built with the CWE examples as few-shot guidance
5. GPT-4o-mini analyses the code 5 times independently
6. Self-consistency voting keeps only bugs confirmed in 3 or more runs
7. Results are displayed with CWE ID, severity, confidence score, location, description and fix

---

## Academic References

- Wang et al. (2022) Self-Consistency Improves Chain of Thought Reasoning. arXiv:2203.11171
- Lewis et al. (2020) Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks. NeurIPS 33
- Brown et al. (2020) Language Models are Few-Shot Learners. NeurIPS 33
- MITRE Corporation (2023) CWE Top 25 Most Dangerous Software Weaknesses. https://cwe.mitre.org/top25/

---

## License

This project was developed as part of a bachelor's thesis at LUT University 2026. For academic use only.