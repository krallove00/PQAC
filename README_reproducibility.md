# Reproducibility README

This repository contains the prototype and experiment scripts for the paper:

The code implements and evaluates a post-quantum anonymous and traceable authentication framework for multi-agent vehicular collaboration. The prototype uses ML-DSA-based anonymous credentials, ML-KEM-based KEM-DEM tracing protection, AEAD encryption for tracing information, and context-bound message authentication.

## 1\. Artifact Overview

The main experiment script is:

```bash
pq\_agent\_vanet\_experiments\_v2\_kemdem.py
```

It supports the following experiment modes:

* `demo`: run a small end-to-end demonstration.
* `all`: run the full experiment suite.
* `compare`: compare the proposed full scheme with baseline schemes.
* `ablation`: evaluate security-component ablations.
* `attack`: validate behavior under typical attacks.
* `scalability`: evaluate performance under different numbers of vehicular agents.
* `levels`: evaluate different NIST post-quantum security levels.

Experiment results are written to the `results/` directory as CSV files.

## 2\. Environment

The prototype was designed for a Linux environment.

Recommended environment:

```text
Operating system: Ubuntu 22.04 or compatible Linux distribution
Python: 3.11
PQC library: liboqs / liboqs-python
Symmetric cryptography: cryptography
Execution mode: single process
```

The exact runtime may vary depending on CPU model, system load, liboqs version, Python version, and cryptographic backend.

## 3\. Installation

### 3.1 Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3.2 Install Python dependencies

If a `requirements.txt` file is provided, install dependencies with:

```bash
pip install -r requirements.txt
```

At minimum, the prototype requires Python bindings for liboqs and the `cryptography` package. If `liboqs-python` is not available from your package index, install it according to the official liboqs-python documentation.

A typical setup is:

```bash
pip install cryptography
pip install liboqs-python
```

Depending on the platform, liboqs may need to be built and installed before installing or importing `liboqs-python`.

## 4\. Quick Start

Run a small end-to-end demonstration:

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode demo
```

This checks the basic workflow:

1. system setup,
2. agent registration,
3. anonymous credential issuing,
4. context-bound collaborative packet generation,
5. anonymous verification,
6. conditional tracing.

## 5\. Full Reproduction

To run the full experiment suite:

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode all --agents 10 --rounds 1000
```

This command may take longer than individual modes because it executes the main benchmark, baseline comparison, ablation, attack validation, scalability-related tasks, and security-level experiments.

## 6\. Recommended Separate Runs

For clearer logs and easier debugging, reviewers are encouraged to run the main experiment groups separately.

### 6.1 Baseline comparison

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode compare --agents 10 --rounds 1000
```

This generates the comparison between the proposed scheme and baseline variants.

### 6.2 Ablation study

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode ablation --agents 10 --rounds 1000
```

This evaluates the effect of removing major security components, such as anonymous credentials, tracing ciphertext, or context binding.

### 6.3 Attack validation

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode attack --rounds 100
```

This validates the expected behavior under typical attacks, including tampering, replay, cross-context misuse, and tracing-key mismatch cases.

For a larger validation run consistent with the paper's 1000-round reporting, use:

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode attack --rounds 1000
```

### 6.4 Scalability evaluation

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode scalability --agent-list 10,30,50,100,200 --rounds 1000
```

This evaluates whether verification and tracing overhead remain stable as the number of vehicular agents increases.

### 6.5 Security-level evaluation

```bash
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode levels --agents 10 --rounds 500
```

This evaluates performance under different post-quantum security-level parameter sets.

## 7\. Output Files

All generated CSV files are placed in:

```bash
results/
```

Expected output files include:

```text
basic\_benchmark.csv
comparison.csv
ablation.csv
refresh\_ablation.csv
attack\_validation.csv
scalability.csv
security\_levels.csv
```

## 8\. Mapping Between Output Files and Paper Results

|Output file|Purpose|
|-|-|
|`basic\_benchmark.csv`|Basic computational cost of the proposed full scheme, including credential issuing, packet generation, verification, and tracing.|
|`comparison.csv`|Comparison with baseline schemes, including direct ML-DSA and reduced variants.|
|`ablation.csv`|Ablation results for major security components.|
|`refresh\_ablation.csv`|Credential-refresh analysis and linkability-exposure trade-off.|
|`attack\_validation.csv`|Functional validation under typical attacks and misuse cases.|
|`scalability.csv`|Performance under different numbers of vehicular agents.|
|`security\_levels.csv`|Performance under different NIST post-quantum security levels.|

## 9\. Reproducibility Notes

1. **Randomness.**  
The prototype uses randomized cryptographic operations. Small variations in timing results are expected across runs.
2. **Hardware dependence.**  
Latency values depend on CPU model, memory, operating system scheduling, Python runtime, and liboqs build configuration.
3. **Single-process measurements.**  
The reported prototype measurements are intended to characterize authentication-layer cryptographic overhead. They are not full PHY/MAC-layer V2X simulations.
4. **No real vehicle data.**  
The experiments use synthetic messages and synthetic agent identities. No real vehicle identity or trajectory data is included.
5. **Warm-up and repeated runs.**  
For stable results, use enough measurement rounds and, if supported by the script, warm-up runs before collecting final statistics.

## 10\. Troubleshooting

### 10.1 `ModuleNotFoundError: No module named 'oqs'`

The Python binding for liboqs is not installed or not visible in the active virtual environment. Activate the virtual environment and reinstall the binding.

```bash
source venv/bin/activate
pip install liboqs-python
```

If this still fails, install liboqs and liboqs-python from source according to the official instructions.

### 10.2 `cryptography` import error

Install or upgrade the package:

```bash
pip install --upgrade cryptography
```

### 10.3 Algorithms unavailable

If ML-DSA or ML-KEM parameter sets are unavailable, the installed liboqs version may not support the required algorithm names. Update liboqs and liboqs-python, then rerun the experiment.

### 10.4 Timing values differ from the paper

This is expected when the CPU, operating system, liboqs version, or Python runtime differs from the paper environment. The important reproducibility checks are:

* the workflow completes successfully;
* valid packets are accepted;
* tampered or replayed packets are rejected;
* tracing recovers the audited identity for valid disputed packets;
* relative trends across baselines, ablations, scalability settings, and security levels are consistent.

## 11\. Suggested Reviewer Workflow

A reviewer who wants a quick functional check can run:

```bash
source venv/bin/activate
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode demo
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode attack --rounds 100
```

A reviewer who wants to reproduce the main tables can run:

```bash
source venv/bin/activate
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode compare --agents 10 --rounds 1000
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode ablation --agents 10 --rounds 1000
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode attack --rounds 1000
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode scalability --agent-list 10,30,50,100,200 --rounds 1000
python3 pq\_agent\_vanet\_experiments\_v2\_kemdem.py --mode levels --agents 10 --rounds 500
```

## 12\. Repository Structure

A recommended repository structure is:

```text
.
├── README.md
├── requirements.txt
├── pq\_agent\_vanet\_experiments\_v2\_kemdem.py
├── results/
│   ├── basic\_benchmark.csv
│   ├── comparison.csv
│   ├── ablation.csv
│   ├── refresh\_ablation.csv
│   ├── attack\_validation.csv
│   ├── scalability.csv
│   └── security\_levels.csv
└── scripts/                  # optional helper scripts
```

## 13\. License


## 14\. Citation



