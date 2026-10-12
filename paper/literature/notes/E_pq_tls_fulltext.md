# Post-quantum cryptographic authentication protocol for industrial IoT using lattice-based cryptography

- **Paper ID:** E
- **DOI:** https://doi.org/10.1038/s41598-025-28413-8
- **Source PDF:** `../pdf/E_pq_tls_pi4.pdf`
- **Pages:** 22
- **Extracted:** auto via pypdf (layout/OCR not perfect; figures are not images)



---

## Page 1

Post-quantum cryptographic 
authentication protocol for 
industrial IoT using lattice-based 
cryptography
Abdul Basit Shahid1,7, Khwaja Mansoor1,2,7, Yawar Abbas Bangash3,4,7, Waseem Iqbal2,5,7 & 
Shynar Mussiraliyeva6,7
The integration of NIST-standardized lattice-based cryptographic algorithms (ML-KEM and ML-DSA) 
into TLS 1.3 enables post-quantum secure authentication for Industrial IoT (IIoT) environments. This 
work implements these algorithms within the X.509 certificate infrastructure and evaluates their 
performance on resource-constrained IIoT hardware (Raspberry Pi 4). Experimental measurements 
covering key generation, encapsulation, decapsulation, and signature operations were obtained using 
a liboqs-enabled TLS 1.3 stack. The results show that PQ TLS 1.3 achieves comparable handshake 
latency to conventional TLS on IIoT-class gateways, with certificate size identified as the dominant 
overhead. These findings confirm the practicality of post-quantum authentication in IIoT systems while 
acknowledging limitations related to the hardware scope and simulated networking. Future work will 
extend validation to field deployments and additional PQC candidates.
Keywords Post-Quantum Cryptography, Authentication, Industrial IoT, Quantum Threats, Lattice-Based 
Cryptography
The advent of quantum computing marks a pivotal shift in computational and cryptographic technologies. Large-
scale quantum computers are now becoming a reality, posing threat to traditional public-key cryptography 1. 
These advancements threaten the network infrastructure of every domain due to the ability of quantum 
algorithms Shor’s to solve hard factorization problem efficiently on which all traditional public-key algorithms 
are based on2.
In response to these threats, Post-Quantum Cryptography (PQC) has become active research area. On July 5, 
2016, NIST initiated an open Request for Proposal invitation process, inviting researchers and mathematicians 
worldwide to propose new quantum-resistant public-key algorithms 3. This process included public comments 
as part of the evaluation, planned to span seven to ten years, aiming to select the best PQ candidate algorithm 
for standardization, with a submission deadline set for November 30, 2017 4. This multiple-round process was 
preparing alternate public-key key encapsulation mechanisms and digital signatures for a future where large-
scale quantum computers could not break public-key algorithms and secure our current digital devices from 
quantum threats5.
The National Cybersecurity Center of Excellence (NCCoE) and NIST held ’Migration to PQC Community 
of Interest’ workshop on Aug 15 2023. The workshop provided platform for industry personnel and government 
sectors to connect with NIST’s PQC project team, participate in panel discussions, and address challenges in 
the PQC transition. NCCoE also established a ’Migration to PQC’ consortium, involving various collaborators 
to develop guidance for organizations preparing for PQC transition6. NCCoE also released NIST SP 1800-38A 
- ’Migration to PQC Preliminary Draft’ which provides a guide and advisory on the necessary replacements of 
devices and technologies to prepare organizations against quantum computing attacks7.
1Faculty of Computing and Artificial Intelligence, Department of Cyber Security, Air University, Islamabad, Pakistan. 
2Department of Information Security, National University of Sciences and Technology (NUST), Islamabad, Pakistan. 
3Department of Smart Computing and Cyber Resilience, DSCCR, Sunway University, Kuala Lumpur, Malaysia. 
4Department of Computer Software Engineering, National University of Sciences and Technology (NUST), 
Islamabad 44000, Pakistan. 5Department of Electrical and Computer Engineering, Sultan Qaboos University, Seeb, 
Muscat, Oman. 6Department of Information Security, Al-Farabi Kazakh National University, Almatey, Kazakhstan. 
7Abdul Basit Shahid, Khwaja Mansoor, Yawar Abbas Bangash, Waseem Iqbal and Shynar Mussiraliyeva contributed 
equally to this work. email: yawarb@sunway.edu.my
OPEN
Scientific Reports |         (2026) 16:9582 1| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports


---

## Page 2

NIST, Cybersecurity and Infrastructure Security Agency (CISA), and the National Security Agency 
(NSA) published a joined factsheet on Aug 17 2023 on quantum readiness which recommends a roadmap 
for organizations on PQC migrations, conducting risk assessments, creating cryptographic inventories and 
coordinating with vendors8.
On Aug 24 2023, NIST finally released three initial drafts of algorithms selected for PQC Standard. These 
documents are FIPS-203 (CRYSTALS-KYBER) now ML-KEM, FIPS-204 (CRYSTALS-Dilithium) now ML-
DSA, and FIPS-205 (SPHINCS+) now SLH-DSA 9. The public comment period for these drafts lasted until 
November 22, 2023.
NSA also released the Commercial National Security Algorithm Suite (CNSA) 2.0 guide which provided a 
complete roadmap for PQC transition for organizations. NSA stated that by 2023, every public and government 
sector must be secured from quantum threats. This includes areas such as operating systems, web services and 
networking equipment. Moreover, the software and firmware signing used in the organization must be quantum-
secure by 2030 as well. CNSA 2.0 recommends algorithms to be used such as, AES-256, Kyber level5, Dilithium 
level5, SHA 384, SHA 512, Leighton-Micali Signature (LMS) with SHA-257 or SHA-192 and the Extended 
Merkle Signature Scheme (XMSS)10.
Considering these developments, our research focuses on the integration of lattice-based cryptographic 
protocols in the Industrial IoT environment, which focuses on migrating to Post-Quantum TLS 1.3 protocol 
and X.509 certificates, aiming to secure IIoT systems against quantum threats.
Amidst these developments, our research is centered on the integration of lattice-based cryptographic 
protocols in the IIoT landscape. We specifically delve into embedding these algorithms within Transport Layer 
Security (TLS) 1.3 and X.509 certificates, aiming to enhance the security and efficiency of communications 
over network systems. TLS 1.3, bolstered by lattice-based cryptography, is positioned as a key defense against 
quantum threats.
The core of our study lies in the practical implementation of specific lattice-based algorithms, such as the 
Ring Learning With Errors (RLWE), within TLS 1.3 and X.509 frameworks. Our objective is to showcase the 
algorithms’ efficiency, implementation feasibility, and advanced security, highlighting their compatibility with 
existing infrastructures and their crucial role in countering quantum computing risks.
This research significantly contributes to the evolving landscape of PQC, offering practical insights and 
applications of lattice-based cryptographic methods. These efforts are particularly vital in securing IIoT systems, 
an area increasingly susceptible to emerging quantum computing threats.
The structure of our paper (Fig. 1) methodically explores the PQC landscape within the Industrial IoT. We 
commence with Section Preliminaries, reviewing existing PQC implementations. This is followed by Section 
IIoT security challenges and requirements, which delves into foundational concepts such as threat models and 
provides an overview of PQC algorithms. In Section Proposed scheme, we tackle the unique security challenges 
inherent in IIoT. Section Benchmarking TLS 1.3 over lattice-based cryptography is dedicated to discussing the 
integration of PQC into TLS 1.3 and X.509. We further extend our research in Section Performance analysis 
by benchmarking TLS 1.3 within a PQC framework. The paper culminates with Section Security analysis and 
Discussion, offering a synthesis of our findings, performance and security analysis and suggesting directions 
for future research in Section Conclusion . This organization ensures a comprehensive understanding of the 
Fig. 1. Paper’s Organization.
 
Scientific Reports |         (2026) 16:9582 2| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 3

quantum computing challenge, the development of PQC, and our focused approach on deploying lattice-based 
cryptography in IIoT contexts.
Related work
Post-quantum authentication for the Internet of Things (IoT) and Industrial IoT (IIoT) has become a pressing 
research area as quantum computing threatens RSA and ECC. A dominant trend across the literature is the 
adoption of lattice-based algorithms such as Dilithium, Kyber, and Falcon, reflecting their selection in the 
NIST PQC process. Complementary schemes include hash-based SPHINCS+ 12, code-based QC-LDPC 15, and 
multivariate or lightweight alternatives such as ANT20.
Lohachab29 introduced a quantum-resistant IoT framework using ECC and PQC, but it lacked a clear 
authentication phase and was vulnerable to replay and MITM attacks. Latif et al. 30 optimized SHA-3-based 
HMAC for quantum resistance, but required persistent message records. Crockett et al. 31 integrated PQC into 
TLS/SSH prototypes, though with outdated NIST candidates, leading to high latency. Code-based designs (e.g., 
Chikouche32) achieved confidentiality but faced replay and timing attacks. Isogeny-based authentication 33 was 
eliminated from NIST due to loop-abort vulnerabilities. Other works proposed lattice-based encryption for 
keyword search34, hybrid PQC-TLS mechanisms23, and vehicular privacy schemes22, but all suffered from either 
overhead, non-standard assumptions, or scalability issues.
Ravi et al.24 proposed LASAN for automotive systems using Kyber/Dilithium via pqm4, but with heavy costs. 
Sikeridis et al. 21 tested PQ signatures in TLS 1.3, but used outdated round-2 candidates. Paul et al. 25 explored 
mixed PQ/traditional certificate chains for TLS 1.3, easing transition but limiting security levels. More recently, 
McLoughlin et al.17 prototyped PQ-DTLS 1.3 on Raspberry Pi 4, showing feasibility but with  6× higher packet 
overhead and  800 KiB extra memory for 100 devices.
Behnia and Y avuz20 introduced the ANT signature, achieving 8–16× faster signing than Dilithium on 8-bit 
A VR nodes, with 5.5× smaller payloads. Banegas et al.19 benchmarked LMS, Dilithium, and Falcon on Cortex-M 
and RISC-V , highlighting trade-offs in verification latency vs. key sizes. Schöffel et al. 18 tested Kyber, SABER, 
NTRU, and SIKE on Cortex-M4, finding 2.5–4 KB memory overhead and bandwidth demands surpassing ECC. 
Gupta16 proposed identity-based lattice authentication to minimize certificate load, though without hardware 
validation.
Samandari and Gritti12 tested Dilithium, Falcon, and SPHINCS+ in a three-layer smart-agriculture setting, 
showing 45% reduced communication overhead when offloading to gateways. In a follow-up13, they compared 
signatures vs. KEMs in MQTT , finding KEMs 71% faster but with message sizes up to 17 KB. Kumari et al. 15 
proposed a lattice/code hybrid reducing authentication delay by 23%, validated via FPGA. Liu et al.28 presented 
a lattice-based multi-party collaborative protocol, resistant to replay and desynchronization attacks.
Prajwal et al.14 combined qPUFs, XOR, and hashing for IIoT authentication on NodeMCU, formally verified 
with Scyther. Tawfeeq et al. 11 applied Dilithium in drone networks for mission-critical authentication. Other 
sectoral adaptations include fog computing26, vehicular communication22, and industrial OPC-UA protocols23.
Overall, PQC-based authentication is feasible for IoT/IIoT , but challenges persist: (i) signature sizes and 
certificate overhead remain high, (ii) latency and memory demands strain resource-constrained devices, (iii) 
security comparison is inconsistent [our work] vs. Scyther14), and (iv) many proposals lack real-world or large-
scale evaluation. While hierarchical or hybrid designs reduce latency by 23% and communication by 45%, 
they often introduce new complexities in scalability and certificate management. Our work advances this line 
by combining Dilithium and Kyber in a server-assisted, CA-based four-phase protocol, and experimentally 
deployed on Raspberry Pi, addressing both security rigor and IIoT-specific resource constraints (see table. 1).
Preliminaries
IIoT system model
We adopt a three-tier IIoT architecture with (i) edge devices (sensors/actuators/controllers, often MCU-class 
and battery powered), (ii) platform/edge gateways (Linux/SBC nodes aggregating field buses to IP), and (iii) 
enterprise/back-end services (data/PKI/management) (Fig. 2).
Data move upward with increasing aggregation and latency; control may flow downward with real-time 
constraints. Authentication can terminate at gateways (common in brownfield deployments) or at servers, while 
devices initiate client authentication as policy dictates. Links are lossy and jittery; clocks on controllers may drift 
by tens of milliseconds.
Threat model
We consider active network adversaries with harvest-now-decrypt-later intent and local attackers with physical 
proximity to edge devices.
Capabilities. Packet injection/replay/downgrade; transcript observation; compromise of outdated classical 
algorithms; local timing/power side-channels and limited fault injection on edge MCUs; software supply-chain 
tampering of firmware images.
Assets. Session keys; device identities (certificates/keys); firmware; control commands; telemetry.
Attack surfaces. (1) Network: replay/MiTM/downgrade; (2) Endpoint: side-channels, key exfiltration from 
insecure NVM; (3) Lifecycle: rogue/expired certificates, clock skew undermining freshness, malicious update 
paths.
Model. Analysis follows a CK-style authenticated key-exchange view with explicit entity authentication and 
channel key indistinguishability. KEMs are assumed IND-CCA2 and signatures EUF-CMA secure under their 
standard lattice assumptions; lossy links and retransmissions are accounted for.
Scientific Reports |         (2026) 16:9582 3| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 4

Security goals
The Industrial Internet of Things (IIoT) demands security mechanisms that ensure the reliability, confidentiality, 
and integrity of data across heterogeneous and resource-constrained environments. The key security goals can 
be summarized as follows: 
 1. Mutual authentication: Ensure that both the device and the control server can verify each other’s identities 
to prevent unauthorized access or impersonation.
 2. Forward secrecy:  Session keys must remain secure even if long-term device credentials are later compro -
mised, preserving confidentiality over time.
 3. Replay and downgrade resistance:  Communication protocols should prevent attackers from reusing cap -
tured messages or forcing negotiation to weaker cryptographic parameters.
 4. Efficiency on constrained nodes: Security operations must remain lightweight to meet IIoT devices’ limita-
tions in memory, processing power, and energy consumption.
 5. Side-channel resilience: Implementations should minimize information leakage through timing, power, or 
electromagnetic emissions, ensuring robustness against physical and microarchitectural attacks.
Post-quantum cryptography
NIST’s PQC effort has selected lattice-based ML-KEM (CRYSTALS-Kyber) for key establishment and lattice-
based ML-DSA (CRYSTALS-Dilithium) and Falcon, plus hash-based SPHINCS+, for signatures3,35. We use the 
term “Kyber” for ML-KEM and “Dilithium” for ML-DSA.
Ref. Purpose Technique Limitations
11 Mission-critical authentication for Internet of 
Drones (IoD)
Dilithium-based signatures integrated into flight 
control/auth
• Limited implementation details • No hardware 
profile/scalability study • Air-to-ground latency not 
evaluated
12 Three-layer IIoT auth offloading in smart 
agriculture
Gateway offloading; eval Dilithium/Falcon/ 
SPHINCS+; hierarchical design
• Gateway complexity/cert management
• No large-scale field deployment
13 Compare signature vs KEM-based auth over 
MQTT
MQTT auth; KEMs faster (71%) but larger messages 
(up to 17 KB)
• Bandwidth overhead at brokers
• No stress tests under lossy links
14 qPUF-aided IIoT authentication on NodeMCU qPUFs + XOR + hashing; Scyther-based validation • qPUF practicality/availability concerns
• Not aligned with NIST PQ standard primitives
15 Hybrid lattice/code for smart-home auth LWE + QC-LDPC; FPGA validation; 23% delay 
reduction
• Complexity of hybrid design
• Large public parameters; deployment fit
16 Reduce certificate overhead via identity-based 
lattice AKE IBE-style lattice AKE to minimize PKI header • No hardware evaluation
• PKG trust/escrow implications
17 Feasibility of PQ-DTLS 1.3 on Raspberry Pi 4 DTLS 1.3 with PQ auth; prototype on RPi4 • ~6× packet overhead; ~800 KiB for 100 devices
• W orkload not IIoT-specific
18 Benchmark PQ KEM/DSA on Cortex-M4 Kyber, SABER, NTRU, SIKE; memory/bandwidth 
profiling
• Higher RAM (2.5–4 KB) and bandwidth than ECC
• Some eliminated candidates
19 Secure update pipelines on MCUs LMS, Dilithium, Falcon on Cortex-M/RISC-V; 
benchmarks
• No end-to-end auth framework
• Trade-offs: key size vs verify latency
20 Lightweight signatures for constrained nodes ANT signature: 8–16× faster sign; 5.5× smaller 
payloads on 8-bit A VR
• Non-standard; security assumptions underexplored
• Side-channel resistance not analyzed
21 PQ Signature Algorithms certificate Study for 
hybrid authentication
OQS-OpenSSL Libraries used on NIST’ s 2nd round 
signature algorithms
• Traditional KEM
• 2nd Round’ s outdated
• and eliminated candidates
22 Conditional privacy-preserving authentication 
in vehicular communication using lattices NTRU-251 based on ISI and ISIS problem
• Partial key exposure attacks
• Heavy computation cost
• Non – Standard PQC
23 Proposed PQC hybrid KEM for the industrial 
communication protocols
Hybrid handshake with RSA-2048 + NewHope512/ 
NTRU/Kyber90s/ LightSaber
• Required more resources
• Not feasible for IoT devices
• Non-standard algorithms
24 Proposed lattice-based secure authentication 
for Automotive
LASAN protocol based on Kyber’ s and Dilithum’ s 
pqm4 library for ECUs authentication on LWE/
LWR problem
• Heavy computation
• High communication cost
• Outdated Library (2nd Round)
25 Proposed Mixed certificate chains for PQ 
Authentication
NIST’ s 3rd Round candidates + traditional ECDSA 
used for mix certificates chain
• Hybrid with traditional ECDSA
• Includes Non-Standard algorithms
• Only NIST security level 2 variants
26
Proposed lattice-based multi-blocks and 
mixed incremental signature protocol for Fog 
computing
Lattice-based incremental hash function scheme on 
SIS problem
• Desynchronization attack
• PQ Algorithm not mentioned
27 Proposed lattice-based PEAKS scheme for 
multi-user settings for IIoT environment
Lattice-based trapdoor scheme under random oracle 
model achieving IND-CKA
• Vulnerable to; Impersonation,
• Replay, side-channel attacks
• PQ Algorithm not mentioned
28 Proposed quantum secure multi-party 
authentication for IIoT environment
Multigeniture authentication using DAPS with Aigis 
and Dilithium
• Replay attack
• Desynchronization attack
• Non-Standard Signature Algorithm
Table 1. Comprehensive Literature Review on Post-Quantum Authentication including IoT and IIoT Settings.
 
Scientific Reports |         (2026) 16:9582 4| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 5

Post-quantum primitive classes
The principal families relevant to IIoT (shown in Fig. 3): lattice-based (LWE/MLWE, NTRU; efficient and broadly 
implemented), code-based (e.g., McEliece; fast but large keys), and hash-based (e.g., SPHINCS+; conservative, 
larger signatures). We focus on lattice primitives for their performance/size balance on embedded targets.
Lattice-based cryptography
Lattice security rests on the hardness of classic problems such as the Shortest Vector Problem (SVP) and Closest 
Vector Problem (CVP), and their module/ring instantiations used by Kyber/Dilithium. We keep brief, IIoT-
relevant summaries here and move tutorials to an appendix to streamline the main text.
Shortest Vector Problem (SVP)
The Shortest Vector Problem (SVP) is one of the foundational problems in lattice theory and has direct 
implications for lattice-based cryptography. A lattice L(B) in Rn is the set of all integer linear combinations of a 
basis B =( b1,b 2,...,b k ). The SVP requires finding the nonzero lattice vector of minimal Euclidean norm, i.e., 
the shortest nonzero vector in the lattice.
Formally, given L(B), the task is to find a nonzero Bx with x ∈ Zk  such that:
 ∥Bx∥≤ γ · λ1(L),
Fig. 2. IIoT 3-Tier System Model (authors’ illustration).
 
Scientific Reports |         (2026) 16:9582 5| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 6

where λ1(L) denotes the first successive minimum of the lattice and γ ≥ 1 is an approximation factor. In the 
exact SVP , γ =1 .
SVP is known to be NP-hard under randomized reductions and is therefore widely regarded as computationally 
intractable. This hardness underpins the security of lattice-based cryptographic constructions. Approximate 
versions (γ-SVP) are particularly relevant for cryptography, as they capture the difficulty of finding vectors that 
are “short enough” rather than optimally short.
The challenge of SVP becomes apparent when the given basis vectors are long or nearly collinear. In such 
cases, much shorter vectors exist as integer combinations of the basis (e.g., 5b1 − 2b2), but identifying them is 
computationally hard. One can visualize the process by expanding a sphere centered at the origin until it first 
intersects a nonzero lattice point; this first point represents the shortest vector (see Fig. 4).
Algorithms such as LLL (Lenstra–Lenstra–Lovász) reduction and its stronger variants (BKZ, BKZ-2.0) can 
find relatively short vectors, but they cannot solve SVP exactly in high dimensions. Even approximate solutions 
remain difficult beyond modest approximation factors. This intractability is precisely what makes SVP a 
cornerstone assumption in post-quantum cryptography: its presumed hardness ensures security against both 
classical and quantum adversaries.
Closest Vector Problem (CVP)
The Closest Vector Problem (CVP) generalizes SVP and is equally important in lattice theory and cryptography. 
Given a lattice L(B) and a target vector t ∈ Rn, the goal is to identify the lattice vector Bx closest to t:
Fig. 4. Shortest Vector Problem (SVP). The shortest vector may be a nontrivial linear combination, e.g., 
5b1 − 2b2.
 
Fig. 3. Post-quantum primitive families.
 
Scientific Reports |         (2026) 16:9582 6| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 7

∥Bx − t∥≤ γ · µ(L, t),
where µ(L, t) denotes the distance from t to the lattice, and γ is an approximation factor.
Visually, CVP asks: given a lattice defined by basis vectors b1,b 2 and a target t, which lattice point lies nearest 
to t? Whereas SVP seeks the shortest vector from the origin, CVP seeks the closest vector to an arbitrary target 
point 5.
CVP is at least as hard as SVP and is often more difficult. Approximating CVP within certain factors is 
NP-hard, and no efficient algorithms are known in general. Approximate versions (Approx-CVP) are useful 
in practice, particularly in cryptography. For example, in Learning With Errors (LWE)-based encryption, 
decryption essentially reduces to an instance of CVP: given a noisy target vector, recover the closest lattice point 
that corresponds to the original message. Thus, the presumed hardness of CVP underpins the security of widely 
deployed PQC candidates such as Kyber and FrodoKEM.
Shortest Independent Vector Problem (SIVP)
The Shortest Independent Vector Problem (SIVP) extends the hardness of SVP to multiple dimensions. Instead 
of finding a single short vector, SIVP requires finding n linearly independent short vectors, where n is the rank 
(dimension) of the lattice.
Formally, given a lattice L(B), the goal is to find linearly independent vectors Bx1, Bx2,..., Bxn ∈L  such 
that:
 max
i
∥Bxi∥≤ γ · λn(L),
where λn(L) denotes the n-th successive minimum of the lattice.
Conceptually, one can think of expanding a sphere around the origin until it encloses n linearly independent 
lattice vectors. These vectors collectively approximate the geometry of the lattice at the n-th successive minimum 
λn. Unlike SVP , which focuses only on λ1, SIVP requires a full “short basis” of the lattice.
As with SVP and CVP , approximate formulations of SIVP are typically considered, where the requirement is 
to find vectors not much longer than λn. Approximate SIVP remains hard in high dimensions and is a central 
assumption in lattice-based cryptography. Indeed, worst-case to average-case reductions show that solving 
approximate SIVP is as hard as breaking Learning With Errors (LWE), thereby grounding the security of many 
lattice-based primitives 6.
In summary, SVP , CVP , and SIVP collectively form the hardness foundation of lattice-based cryptography. 
Their computational intractability ensures that schemes based on these problems, such as NTRU, Kyber, and 
Dilithium, remain secure even against quantum adversaries. T ogether, they provide the theoretical guarantees 
that make lattice-based cryptography one of the most promising families of post-quantum secure schemes.
Why lattices for IIoT
Lattice primitives provide (i) post-quantum assurance with widely analyzed assumptions (LWE/MLWE, NTRU), 
(ii) performance suitable for embedded targets, and (iii) standards alignment with NIST’s selections. We avoid 
tutorial exposition and instead provide actionable guidance below.
Selected PQC algorithms
ML-KEM (CRYSTALS-Kyber) Module-LWE KEM with IND-CCA2 security via FO transform; commonly 
profiled at levels roughly corresponding to Cat. I/III/V (Kyber512/768/1024) 36. We use Kyber for handshakes 
and derive application keys via HKDF . Constant-time, low-RAM implementations exist for MCU/SBC platforms 
(see table. 2).
ML-DSA (CRYSTALS-Dilithium) Module-SIS/LWE signature with EUF-CMA security; recommended at 
levels roughly mapping to Cat.  II/III/V (Dilithium2/3/5) 37. We adopt constant-time sampling and 12-round 
Keccak-based expanders where appropriate (see table. 3).
Fig. 5. Closest Vector Problem (CVP). The goal is to find the lattice point closest to target t.
 
Scientific Reports |         (2026) 16:9582 7| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 8

Parameterization and device profiles for IIoT
To connect primitives to hardware constraints, we define pragmatic profiles (table. 4):
Rationale. Sensors prioritize smaller ciphertexts and faster decapsulation; edges trade modest overheads for 
higher assurance; gateways/servers anchor PKI and can absorb Cat. V costs. These choices bound handshake 
bytes and peak memory while retaining clear migration paths.
IIoT security challenges and requirements
Industrial IoT (IIoT) couples long-lived, heterogeneous devices with real-time control. Security controls 
therefore must (i) authenticate endpoints under lossy links and clock drift, (ii) bound latency and memory 
on constrained nodes, and (iii) remain secure against harvest-now-decrypt-later quantum adversaries. Unlike 
generic IoT surveys, we link each challenge to a post-quantum mechanism and to the concrete design choices 
used in our protocol (see Fig. 7).
Requirements mapped to PQC and Our scheme
We employ lattice-based ML-KEM (Kyber) for key establishment and ML-DSA (Dilithium) for authentication 
(see 5). Authentication terminates at gateways or servers depending on the device tier; sensors can perform 
client authentication when mandated by policy.
Tier KEM Signature
Sensor (MCU) Kyber512 Dilithium2
Edge (SBC) Kyber768 Dilithium3
Gateway/Server Kyber1024 Dilithium5
Table 4. Recommended PQ suites by device tier (deployment profiles).
 
DSA Security (indicative) Public Key (bytes) Signature (bytes)
Dilithium2 Cat. II 1312 2420
Dilithium3 Cat. III 1952 3293
Dilithium5 Cat. V 2592 4595
Table 3. Indicative sizes for Dilithium parameter sets.
 
KEM Security (indicative) Public Key (bytes) Ciphertext(bytes)
Kyber512 Cat. I 800 768–800
Kyber768 Cat. III 1184 1088
Kyber1024 Cat. V 1568 1568
Table 2. Indicative sizes for Kyber parameter sets.
 
Fig. 6. Shortest Independent Vector Problem (SIVP). The task is to find n short, linearly independent vectors.
 
Scientific Reports |         (2026) 16:9582 8| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 9

Security requirements
Authentication. Mutual authentication uses Dilithium certificates (server-side mandatory; client-side policy-
driven). Profiles in Parameterization and device profiles for IIoT  select Dilithium2/3/5 by tier; this directly 
answers low-power vs. high-assurance deployments.
Challenge PQC relevance (mechanism) Our scheme choice (why) Impact in IIoT
Low-power sensors (MCU, 
battery)
Handshake and signatures must fit tight 
RAM and energy budgets. Use smallest 
practical KEM/DSA.
Kyber512 + Dilithium2 at sensors Parameterization and 
device profiles for IIoT; offload certificate path checks to 
gateway when policy permits.
Reduces on-device bytes and cycles; 
bounded peak RAM; minimizes 
retransmissions on lossy links.
Edge gateways (SBC, Linux) Can sustain stronger parameters while 
aggregating many sessions.
Kyber768 + Dilithium3 at edges Parameterization and 
device profiles for IIoT to raise assurance without large 
latency penalty.
Balances throughput and security for 
broker/MQTT/TLS concentrators.
High-throughput/back-end
Anchors PKI and terminates many 
handshakes; prioritizes strongest 
security.
Kyber1024 + Dilithium5 at gateways/servers for anchoring 
trust.
Future-proofs against long-term 
attacks; negligible impact on server-
class hardware.
Harvest-now-decrypt-later Classical DH/ECDH handshakes are 
vulnerable to future decryption.
All sessions use Kyber KEM for key establishment; hybrid 
optional if policy requires.
Confidentiality of captured traffic 
preserved post-quantum.
Replay/downgrade on lossy links Negotiation can be forced to weaker 
suites; retransmissions can enable replay.
TLS 1.3 with PQ suites only; strict signature-algorithm/
KEM allow-lists; transcript-bound keys.
Prevents downgrade; nonces + 
transcript hashing block replay under 
packet loss.
Side-channels on edge MCUs Secret-dependent timing in PQC can 
leak keys.
Constant-time Kyber/Dilithium implementations; no 
secret-dependent branches; RNG health checks.
Mitigates timing/power leakage; aligns 
with Security Goal 5 Security goals.
Certificate size/PKI overhead PQ signatures/keys enlarge X.509 objects 
and handshake bytes.
Short-lived device certs; compressed chains; gateway-
assisted validation; Dilithium2 at the edge where feasible.
Keeps handshake bytes B manageable; 
reduces revalidation load on sensors.
Firmware/auth update integrity Long device lifetimes require quantum-
safe signing of artifacts.
Dilithium signing for images; verification on device/
gateway; secure boot roots on gateways.
Prevents supply-chain tampering 
across lifecycle.
Real-time and jitter sensitivity Control loops require capped handshake 
latency Ths .
Tiered parameters Parameterization and device profiles for 
IIoT; session resumption and PSK for steady-state.
Meets latency budgets; avoids frequent 
full PQ handshakes in tight loops.
Table 5. IIoT challenges mapped to PQC mechanisms and our deployment choices.
 
Fig. 7. IIoT challenges and requirements (overview).
 
Scientific Reports |         (2026) 16:9582 9| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 10

Key establishment and forward secrecy. All handshakes employ Kyber (ML-KEM). Optional hybrid modes 
are supported for regulatory migration but disabled by default to avoid downgrade complexity.
Access control. Authorization is handled at the application layer, but credential binding anchors to PQ X.509 
identities (reduces spoofing when classical roots are deprecated).
Data security.  Application keys are derived from PQ handshakes (HKDF) and used with AEAD; 
confidentiality remains safe against HNDL threats.
Maintainability/resilience. PQ-signed firmware and config updates; session resumption to cap latency; 
certificate rotation policies tuned to device class.
Monitoring. PQ does not replace IDS/telemetry; however, handshake metadata (suite, sizes) enables policy 
checks to detect illicit non-PQ sessions.
IIoT-specific challenges
Long-lived components. Use PQ roots and Dilithium-signed updates; define migration paths for legacy nodes 
via gateway termination.
High connectivity / IT–OT convergence. Enforce PQ-only TLS on northbound links; use Kyber/Dilithium 
profiles per tier to maintain throughput on aggregation points.
Device proliferation.  Automate enrollment with PQ certificate templates; prefer gateway-assisted chain 
validation to keep MCU costs low.
Human error / sabotage. Short-lived credentials, revocation via gateway CRLs/OCSP; secure default suites 
(no classical fallbacks).
Why post-quantum for IIoT
Classical ECDH/ECDSA handshakes jeopardize confidentiality under harvest-now-decrypt-later. Lattice-based 
Kyber/Dilithium provide efficient PQ security on embedded and edge platforms, and–when parameterized 
per device tier–respect IIoT latency and memory constraints. Our server-assisted design (gateways/servers 
terminate heavy validation; sensors use lighter profiles) connects PQC directly to the operational realities of 
IIoT, avoiding generic “checklists” while meeting the goals in Security goals.
Proposed scheme
Our contribution is a migration strategy that embeds lattice-based post-quantum algorithms into the full TLS 1.3 
stack for IIoT environments. Unlike prior survey-style or purely theoretical works, we (i) integrate ML-DSA 
(CRYSTALS-Dilithium) into X.509 certificates for authentication, (ii) adopt ML-KEM (CRYSTALS-Kyber) for 
handshake key exchange, and (iii) benchmark the complete protocol on IIoT-class hardware (Raspberry Pi 4). 
This combination–practical TLS 1.3 migration, certificate integration, and performance/resource evaluation–
addresses the unique requirements of IIoT, where devices are resource-constrained, expected to operate for 
decades, and must resist harvest-now-decrypt-later threats.
Post-quantum X.509 certificates
A central aspect of our scheme is adapting X.509 certificates to lattice-based signatures. Figure  8 illustrates the 
structure of a PQ X.509 certificate embedding Dilithium public keys and signatures. Compared with classical 
ECDSA/RSA certificates, sizes increase by 1.5–2.5 ×, but remain manageable when offloaded to gateways. For 
constrained clients, validation of short-lived end-entity certificates can be deferred to gateways or performed 
incrementally.
In our implementation:
• The Root CA uses Dilithium-5 to anchor long-term trust.
• Intermediate and end-entity certificates employ Dilithium-2/3, balancing security with device verification 
costs.
Fig. 8. Lattice-based X.509 certificate with Dilithium signatures.
 
Scientific Reports |         (2026) 16:9582 10| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 11

• Certificate chains are compressed and rotated frequently, reducing the overhead on sensors.
This design preserves PKI compatibility while enabling IIoT deployments to transition without abandoning 
existing trust infrastructures.
Post-quantum TLS 1.3 handshake
We extend the TLS 1.3 handshake (Fig. 9) by replacing classical primitives with lattice-based counterparts:
• Key establishment: The ephemeral Diffie–Hellman exchange is replaced by Kyber encapsulation/decapsula-
tion (Kyber512 for MCUs, Kyber768 for gateways, Kyber1024 for servers).
• Authentication: CertificateVerify and Finished messages are signed with Dilithium, ensuring EUF-CMA 
security even against quantum adversaries.
• Optional client authentication: When required by policy (e.g., actuator-to-gateway links), clients authenti-
cate using Dilithium-2.
The handshake flow mirrors classical TLS 1.3, but with larger key and signature objects. Our evaluation 9 quantifies 
these costs: on Raspberry Pi 4, handshake completion time increased by ∼1.6× relative to ECDHE+ECDSA, 
with RAM consumption rising by ∼600  KiB. However, these overheads remain acceptable for gateways and 
servers, while sensors benefit from shorter parameter sets and gateway-assisted validation.
Why IIoT needs this scheme
IIoT deployments differ from enterprise IT in three key ways: 
 1. Resource-constrained nodes.  Kyber512 and Dilithium2 provide quantum resistance while fitting MCU-
class limits.
 2. Long-lived devices. Equipment expected to operate for 10–20 years must resist harvest-now-decrypt-later 
attacks; PQC ensures confidentiality of today’s traffic remains intact against future quantum adversaries.
 3. Gateway-centric trust. Offloading certificate chain validation and large signature operations to gateways 
enables constrained sensors to participate securely without excessive overhead.
Fig. 9. TLS 1.3 handshake adapted with Kyber KEM and Dilithium signatures.
 
Scientific Reports |         (2026) 16:9582 11| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 12

By combining TLS  1.3 migration with lattice-based primitives and demonstrating feasibility on real IIoT-
class hardware, our scheme offers a practical, forward-compatible path that balances quantum security, 
interoperability, and resource constraints.
Benchmarking TLS 1.3 over lattice-based cryptography
We benchmark a complete post-quantum (PQ) TLS  1.3 stack tailored to IIoT constraints, focusing on (i) 
microbenchmarks of KEMs and DSAs, (ii) PQ-ready X.509 sizes, and (iii) end-to-end TLS 1.3 handshake costs. 
Our goal is not to re-establish known desktop/server results, but to characterize performance on IIoT-class 
hardware and provide deployment guidance by device tier.
We build on prior TLS/PQC evaluations: Sikeridis et al. (Intel CPUs/cloud) 21, Tasopoulos et al. (STM32 
microcontrollers; performance/energy)38,39, and Paul et al. (mixed certificate chains across notebook/cloud) 25. 
Our results complement these by targeting a common IIoT gateway platform (Raspberry Pi 4) and by reporting 
end-to-end handshake/footprint with Kyber/Dilithium and PQ X.509.
Experimental setup
Platform. Raspberry Pi  4 Model B (Broadcom BCM2711, quad-core Cortex-A72 @  1.8  GHz, 4  GB 
LPDDR4-3200), Ubuntu 23.04. The device plays both client and server roles to isolate cryptographic costs.
Software. PQ algorithms from liboqs 0.8.0 ; TLS from wolfSSL 5.6.3 (OpenSSL-compatible 
fork) integrated with liboqs for PQ TLS 1.3 and PQ X.509 generation. Cipher suite: TLS_AES_256_GCM_
SHA384. We evaluate Kyber (512/768/1024) and Dilithium (2/3/5); selected classical baselines are included for 
reference.
Methodology. Client/server processes run on the same host (loopback) to eliminate variable W AN/LAN 
latency and isolate cryptographic and framing overheads. Unless stated, averages are over repeated runs with 
warm caches.
Limitations. Results reflect one IIoT-class platform, local loopback (no network delay/jitter), and one TLS 
implementation. This isolates crypto and certificate handling but under-represents real deployments with hops, 
loss, and congestion Threats to validity and limitations.
Benchmark repeatability and metrics.
Each benchmark was executed 30 consecutive times on the Raspberry Pi 4 testbed under identical thermal and 
CPU-governor conditions (performance mode, 1.8 GHz). The mean and standard deviation were computed 
for all timing metrics. Handshake times and key/verify operations are reported in milliseconds (ms), while key 
and ciphertext sizes are in bytes (B). All tests were performed on a local loopback network to exclude variable 
network latency; therefore, results reflect cryptographic computation only.
KEM microbenchmarks (key establishment)
Table 6 reports sizes and operation timings for Kyber (512/768/1024) and classical ECDH/FFDHE baselines 
(OpenSSL  3.0.8). Despite larger objects, Kyber shows low keygen/encap/decap latency on RPi4. Figure  11 
contrasts public/secret/ciphertext sizes; Fig. 10 (log scale) shows Kyber’s consistently low operation times relative 
to classical key agreement. These confirm that PQ KEM cost is compatible with gateway-class IIoT hardware, 
while giving the confidentiality benefits against harvest-now-decrypt-later.
DSA microbenchmarks (authentication)
Table 7 presents Dilithium (2/3/5), Falcon (512/1024), and classical ECDSA/RSA. Figures 13 and 12 summarize 
size and timing trade-offs. Dilithium offers strong verification throughput with moderate signing costs, making 
it suitable for server/gateway authentication and, where policy requires, client authentication on capable nodes.
PQ X.509 object sizes
Table 8 and Fig.  14 quantify key/CSR/certificate sizes for Dilithium vs. RSA. PQ certificates are 1.5–6 × larger 
than ECDSA/RSA, reinforcing the need for gateway-assisted validation and short chains in sensor-facing 
deployments. This overhead is the principal contributor to increased handshake bytes (next subsection).
KEM Algorithm Hardness Problem Public key Secret key Cipher text
Key gen En-caps De-caps
Mean ops/s Mean ops/s Mean ops/s
Kyber-512 Module Learning With Errors 800 1632 768 0.021 47619.050 0.028 35714.290 0.020 50000.000
Kyber-768 1183 2400 1088 0.034 29411.760 0.041 24390.240 0.030 33333.330
Kyber-1024 1568 3168 1568 0.046 21739.130 0.056 17857.140 0.042 23809.520
P-2561 Elliptic Curve Discrete Logarithm 32 32 70 12.711 78.670 0.1004 7711.5004 - -
P-3842 48 48 103 18.082 55.300 1.5004 673.0004 - -
P-5213 66 66 138 14.581 68.580 0.7004 1444.4004 - -
FFDHE 3072 Finite Field Discrete Log 256 256 256 32.100 31.090 1.8004 554.9004 - -
Table 6. Key Exchange Algorithms. 1ECDH 256-bits (nistp256), 2ECDH 384-bits (nistp384), 3ECDH 521-bits 
(nistp521), 4Key agreement, Units: Key sizes/ciphertext (bytes), Mean (ms).
 
Scientific Reports |         (2026) 16:9582 12| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 13

End-to-End PQ TLS 1.3 handshake
We instrument end-to-end handshakes under combinations of Dilithium (auth) and Kyber (KEM), plus a 
SECP256R1 baseline. Figure 15 shows a representative Wireshark trace.
Table  9 reports client/server heap, stack, total communication (bytes), and handshake time (ms) per 
combination. Figures  19, 17 summarize communication and latency and fig. compares stack allocation. Key 
observations:
• Communication. PQ handshakes add tens of kilobytes over classical due to PQ X.509 sizes; nevertheless, in 
our setup several Kyber/Dilithium pairs transmitted less than some classical baselines with larger certificate 
chains.
• Latenc y. Client handshake times for Kyber512/Dilithium2–3 are typically 6.5–8.0 ms; Kyber1024/Dilithium5 
rise toward 12–13 ms. The SECP256R1 baseline spans ∼12–20 ms in our configuration, illustrating that PQ 
does not necessarily imply higher latency on this platform.
Kyber512Kyber768Kyber1024
P-256 P-384 P-521
FFDHE-3072
0
1,000
2,000
3,000
Size in kb
Publickey Secretkey Ciphertext
Fig. 11. “Traditional vs. PQ KEX: Publickey, Secretkey & Ciphetext Sizes.
 
Kyber512Kyber768
Kyber1024
P-256 P-384 P-521
FFDHE-3072
10−2
10−1
100
101
Mean Time in Milliseconds (log scale)
Keygen En-caps De-caps
Fig. 10. Traditional vs. PQ KEX: Keygen, En-caps & De-cap ops.
 
Scientific Reports |         (2026) 16:9582 13| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 14

• Memor y. Heap usage is stable across Kyber variants (73 KB client / 82 KB server) and higher for SECP256R1 
in our build (88 KB / 107 KB). Stack footprints track signature level (Fig. 16).
Performance analysis
This section interprets the benchmarks, positions them relative to prior work, and gives IIoT deployment 
guidance.
Comparative analysis with prior work
TLS on general-purpose CPUs.  Sikeridis et al. 21 reported PQ-TLS latency increases on Intel CPUs and cloud 
instances. Our RPi4 results show Kyber/Dilithium can achieve single-digit to low-two-digit millisecond 
handshakes even on embedded-class SBCs, indicating feasibility for IIoT gateways.
Microcontroller focus. Tasopoulos et al.38,39 emphasized performance/energy on STM32 (Cortex-M). Our 
work complements this by targeting a common gateway tier (Cortex-A72), which often terminates TLS for many 
field devices and must balance throughput with PQ security.
Mixed certificate deployments.  Paul et al. 25 explored mixed classical/PQ chains in notebooks/cloud. In 
contrast, we quantify full PQ chains (Dilithium) and their byte/latency impact in IIoT TLS 1.3.
Lightweight three-party protocols (mobile).  Works such as the anonymous quantum-safe three-party 
AKE for mobile40, the post-quantum authenticated key agreement for mobile communication 41, and the more 
recent Ring-LWE based three-party authenticated key agreement protocol addressing vulnerabilities in prior 
schemes42 highlight protocol-level constructions and simulation-driven evaluations aimed at mobile and 
constrained environments. Our study differs by integrating PQ primitives into TLS 1.3 with X.509 , reporting 
Dilithium2Dilithium3Dilithium5
P-256P-384P-521
RSA-2048RSA-3072
10−1
100
101
102
103
104
105
Mean Time in Milliseconds (log scale)
Keygen Sign Verify
Fig. 12. Traditional vs. PQ DSA: Keygen, Sign & Verify ops.
 
Signature Algorithm Hardness Problem Public key Secret key Signature
Key gen Sign Verify
Mean ops/s Mean ops/s Mean ops/s
Dilithium2 Module Learning with Errors 1312 2528 2420 0.064 15625.000 0.171 5847.950 0.064 15625.000
Dilithium3 1952 4000 3293 0.107 9345.790 0.280 3571.430 0.104 9615.380
Dilithium5 2592 4864 4595 0.168 5952.380 0.334 2994.010 0.164 6097.560
Falcon512 NTRU 897 1281 666 14.642 68.280 0.495 2020.200 0.091 10989.010
Falcon1024 1793 2305 1280 44.012 22.720 0.975 1025.640 0.177 5649.720
P-2561 Elliptic Curve Discrete Logarithm 32 32 70 14.775 67.680 0.100 18165.300 1.200 5690.100
P-384 2 48 48 103 16.762 59.660 1.600 624.500 1.400 706.400
P-521 3 66 66 138 14.880 67.210 0.600 1805.500 1.100 875.200
RSA-2048 Integer Factorization 256 256 256 6618.050 0.150 1.451 689.000 0.043 23486.300
RSA-3072 384 384 384 39709.770 0.030 4.366 229.000 0.092 10843.300
Table 7. Digital Signature Algorithms. 1 ECDSA 256-bits (nistp256) , 2 ECDSA 384-bits (nistp384), 3 ECDSA 
521-bits (nistp521), Units: Key sizes/Signature (bytes), Mean (ms).
 
Scientific Reports |         (2026) 16:9582 14| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 15

concrete certificate sizes, handshake traces, and heap/stack/latency on IIoT-class hardware. These directions are 
complementary: lightweight AKEs focus on minimizing message complexity and enhancing privacy in mobile 
settings, whereas our results demonstrate that standardized TLS with Kyber/Dilithium is already practical for 
deployment at the IIoT gateway tier.
Findings
(F1) Kyber is not the bottleneck on gateways. Despite larger objects, Kyber’s keygen/encap/decap latencies are 
low (Table 6, Fig. 10); handshake time is dominated by certificate processing and I/O framing.
(F2) Dilithium verification scales well.  Verification throughput is high across Dilithium levels (Table  7, 
Fig. 12), suitable for server/gateway auth and client auth on capable nodes.
(F3) X.509 dominates bytes.  PQ certificates inflate handshake size (Table  8, Fig.  14); short-lived EE certs, 
compressed chains, and gateway-assisted validation mitigate costs.
(F4) PQ can match or beat classical latency on RPi4.  In our stack, Kyber512/Dilithium2–3 often achieve 
lower handshake time than SECP256R1 (Table 9, Fig. 17).
Deployment guidance for IIoT
Based on 6:
• Sensors (MCU/very constrained): Prefer gateway termination of TLS where permissible. If clients must au-
thenticate, target Dilithium2 and Kyber512; minimize chain length and use short-lived EE certs.
• Edge gateways (SBC/RPi-class):  Use Kyber768 + Dilithium3 to balance assurance and throughput; enable 
session resumption/PSK to cap control-loop jitter.
• Back-end/gateway anchors: Use Kyber1024 + Dilithium5 to future-proof long-term trust roots and artifact 
signing (firmware/config).
Signature Algorithm
Key Sizes CSR Size
Certificate 
Size
Root EE EE Root EE
Dilithium2 5.17 5.17 5.32 6.00 6.07
Dilithium3 7.96 7.96 7.32 8.00 8.07
Dilithium5 9.95 9.95 9.89 10.5 10.6
Falcon1 2.96 2.96 2.42 3.10 3.17
Falcon5 5.50 5.50 4.42 5.10 5.16
RSA1024 0.912 0.916 0.603 0.904 0.778
RSA2048 1.66 1.66 0.956 1.21 1.09
RSA3072 2.42 2.42 1.27 1.55 1.43
Table 8. Lattice-Based X.509 Certificate and key sizes (Kb).
 
Dilithium2Dilithium3Dilithium5
P-256P-384P-521
RSA-2048RSA-3072
0
1,000
2,000
3,000
4,000
5,000
Size in kb
Publickey Secretkey Signature
Fig. 13. Traditional vs. PQ DSA: Publickey, Secretkey & Signature Sizes.
 
Scientific Reports |         (2026) 16:9582 15| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 16

These recommendations align with the profiles introduced in Parameterization and device profiles for IIoT and 
our end-to-end measurements.
Threats to validity and limitations
Single platform/stack. Results are from one SBC (RPi4) and one TLS stack; different libraries or hardware 
cryptographic accelerators may shift absolute numbers.
No network delay/loss. Loopback testing isolates cryptographic cost but omits W AN/LAN latency, jitter, and 
retransmissions. Field tests with realistic links (Wi-Fi/5G/fieldbus gateways) are left to future work.
Energy not measured. Unlike microcontroller studies39, we did not instrument power draw; this is important 
for battery-powered gateways and is future work.
Security analysis
A sound deployment of PQ-TLS in IIoT requires not only performance evaluation but also security validation 
under a clear threat model. Here, we sketch the analysis of our proposed framework against standard adversarial 
capabilities.
Replay attack resistance
TLS 1.3 includes nonces and ephemeral key exchanges in every handshake. When instantiated with Kyber (KEM) 
and Dilithium (DSA), our PQ-TLS variant inherits replay protection: encapsulated keys are bound to ephemeral 
randomness and session transcripts, making replayed messages invalid. Thus, prior handshake captures cannot 
establish valid sessions.
Fig. 15. PQ-TLS 1.3 Handshake Packets Captured in Wireshark.
 
Dilithium2Dilithium3Dilithium5RSA1024RSA2048RSA3072
0
2
4
6
8
10
Size in kb
Root key EE key Root cert EE cert
Fig. 14. Traditional vs. PQ x.509: Keys & Certificates Sizes.
 
Scientific Reports |         (2026) 16:9582 16| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 17

Man-in-the-Middle (MITM) resistance
Under the Canetti–Krawczyk (CK) model for authenticated key exchange, PQ-TLS inherits forward secrecy 
and channel authentication. In our scheme, authenticity is provided by Dilithium-signed X.509 certificates; 
secrecy is guaranteed by Kyber KEM. A MITM adversary cannot generate valid certificate chains or complete 
KEM decapsulation without the legitimate private key, ensuring confidentiality and integrity against active 
interception.
Ky
ber P256
70
80
90
100
110
Memory Allocations
Client Server
Fig. 16. Memory allocations for clients/servers: Kyber(all variants) vs P256.
 
Authentication
Key Exchange Algorithm
Heap Stack (kb)
Comminution 
(kb)
Handshake 
(ms)
Client/Server Client/Server Client Server Client Server Client Server
Dil3-Dil2
Kyber512 73/82
53.656 82.219 123.037 127.185 7.169 4.017
Dil5-Dil2 53.656 115.188 133.867 138.823 10.911 5.768
Dil2-Dil3 82.813 53.063 126.299 123.923 6.572 3.198
Dil5-Dil3 82.813 115.188 145.562 147.256 8.799 5.945
Dil2-Dil5 115.781 53.063 137.938 134.753 7.186 3.997
Dil3-Dil5 115.781 82.219 146.370 146.447 7.832 4.095
Dil3-Dil2
Kyber768 73/82
53.656 82.219 125.162 128.185 6.818 3.647
Dil5-Dil2 53.656 115.188 135.992 139.823 7.913 3.747
Dil2-Dil3 82.813 53.063 128.424 124.923 11.787 6.096
Dil5-Dil3 53.656 115.188 147.687 148.256 12.161 7.536
Dil2-Dil5 115.781 53.063 140.062 135.753 14.458 9.121
Dil3-Dil5 115.781 82.219 148.495 147.447 8.666 5.130
Dil3-Dil2
Kyber1024 73/82
53.656 82.219 127.600 129.497 8.202 4.510
Dil5-Dil2 53.656 115.188 138.43 141.136 13.477 12.102
Dil2-Dil3 82.813 53.063 130.861 126.235 8.445 3.788
Dil5-Dil3 82.813 115.188 150.124 149.568 8.707 4.091
Dil2-Dil5 115.781 53.063 142.500 137.065 8.083 4.563
Dil3-Dil5 115.781 82.219 150.933 148.760 12.782 8.809
Dil3-Dil2
SECP256R1 88/107
53.656 82.477 162.433 166.021 12.208 8.042
Dil5-Dil2 53.656 115.477 173.263 177.659 17.110 16.272
Dil2-Dil3 82.813 53.352 165.694 162.759 8.459 3.788
Dil5-Dil3 82.813 115.477 184.957 186.092 20.236 19.176
Dil2-Dil5 115.781 53.352 177.333 173.589 10.129 10.665
Dil3-Dil5 115.781 82.477 185.766 185.283 14.702 14.494
Table 9. Post-Quantum TLS 1.3 Handshake.
 
Scientific Reports |         (2026) 16:9582 17| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 18

Forward secrecy and key compromise
By relying on ephemeral KEM key pairs (Kyber), session keys are independent of long-term keys. Even if a 
device’s Dilithium private key is later compromised, past sessions remain secure. This property is critical for 
long-lived IIoT nodes vulnerable to eventual key extraction.
Side-channel considerations
Resource-constrained IIoT devices are especially prone to timing, power, and electromagnetic side-channel 
attacks. Our experiments on Raspberry Pi do not capture these risks. However, lattice-based primitives like 
Kyber and Dilithium are under active hardening for side-channel resistance, with masked and constant-time 
implementations. We acknowledge this as a limitation and an area for future hardware-level evaluation.
Dil3-Dil2-K
yb512
Dil5-Dil3-K
yb512
Dil3-Dil5-K
yb512
Dil3-Dil2-Kyb768Dil5-Dil3-K
yb768
Dil3-Dil5-K
yb768
Dil3-Dil2-K
yb1024
Dil5-Dil3-K
yb1024
Dil3-Dil5-K
yb1024
Dil3-Dil2-P256Dil5-Dil3-P256Dil3-Dil5-P256
60
80
100
120
Stack Allocs (kb)
Client Server
Fig. 18. Authentication/Key-Exchange Algorithm combinations comparing memory stack allocations.
 
Dil3-Dil2-K
yb512
Dil5-Dil3-K
yb512
Dil3-Dil5-K
yb512
Dil3-Dil2-K
yb768
Dil5-Dil3-K
yb768
Dil3-Dil5-K
yb768
Dil3-Dil2-K
yb1024
Dil5-Dil3-K
yb1024
Dil3-Dil5-K
yb1024
Dil3-Dil2-P256Dil5-Dil3-P256Dil3-Dil5-P256
5
10
15
20
AvgT ime in Milliseconds
Client-Handshake Server-Handshake
Fig. 17. Authentication/Key-Exchange Algorithm combinations comparing client/server handshake.
 
Scientific Reports |         (2026) 16:9582 18| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 19

Summary
Our analysis shows that PQ-TLS 1.3 with Kyber and Dilithium maintains resistance to replay and MITM attacks 
under the CK model, provides forward secrecy, and inherits TLS transcript binding. Side-channel resistance 
remains an open practical challenge, but the integration of hardened libraries (e.g., liboqs with masked 
implementations) offers a mitigation path.
Discussion
Deployment challenges
While Raspberry Pi benchmarks show PQ-TLS feasibility, actual IIoT deployments face constraints:
• Memory and storage limits: PQ X.509 certificates (5–10 KB) strain devices with 256 KB flash.
• Backward compatibility: IIoT deployments often require hybrid certificates (RSA/ECDSA + Dilithium) to 
interoperate with legacy systems.
• Update lifecycles:  Long-lived IIoT devices may lack secure update channels, complicating cryptographic 
agility.
Standardization landscape
Our scheme aligns with active standardization efforts. IETF drafts on PQ-TLS, NIST’s post-quantum competition 
finalization, and the U.S. CNSA 2.0 roadmap all mandate lattice-based algorithms (Kyber, Dilithium) for near-
term adoption. PQ X.509 certificate encoding, though still experimental, is under evaluation by OQS–OpenSSL 
and ETSI technical groups, suggesting that interoperability testing will soon be possible.
Hardware feasibility
We selected Raspberry Pi 4 as a baseline gateway device, representing mid-tier IIoT controllers. Results show PQ 
handshakes under 15 ms and stable memory use (73–82 KB heap). However, microcontrollers (e.g., Cortex-M, 
1 MB RAM) present steeper challenges. While Kyber-512 may be feasible with lightweight libraries, Dilithium 
signatures and full PQ certificates remain prohibitive without hardware acceleration or FPGA offloading. These 
constraints highlight the importance of tiered deployment strategies: PQ-TLS at gateways, lightweight AKEs at 
edge sensors.
Sector-specific recommendations
Beyond generic deployment, our benchmarks suggest tailored algorithm profiles for different sectors:
Energy & Utilities: Dilithium-5 + Kyber-1024 for highest assurance.
Oil & Gas: Dilithium-3/5 + Kyber-768 for balanced latency/security.
Mining & Agriculture: Dilithium-2 + Kyber-512 for reduced overhead.
Smart Cities & Manufacturing: Dilithium-3/5 + Kyber-768 for scalability.
Healthcare: Dilithium-3/2 + Kyber-1024 for strong privacy guarantees.
This mapping demonstrates how PQ-TLS parameterization can align with sectoral risk and resource profiles.
Dil3-Dil2-K
yb512
Dil5-Dil3-K
yb512
Dil3-Dil5-K
yb512
Dil3-Dil2-K
yb768
Dil5-Dil3-K
yb768
Dil3-Dil5-K
yb768
Dil3-Dil2-K
yb1024
Dil5-Dil3-K
yb1024
Dil3-Dil5-K
yb1024
Dil3-Dil2-P256Dil5-Dil3-P256Dil3-Dil5-P256
120
140
160
180
AvgT ime in Milliseconds
Client-Communication Server-Communication
Fig. 19. Authentication/Key-Exchange Algorithm combinations comparing client/server communication kb 
used.
 
Scientific Reports |         (2026) 16:9582 19| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 20

Conclusion
This work demonstrates the practical feasibility of deploying TLS 1.3 secured with lattice-based post-quantum 
algorithms in Industrial IoT (IIoT) environments. The study integrates NIST-standardized CRYSTALS-
Kyber (KEM) and CRYSTALS-Dilithium (DSA) within TLS  1.3 and X.509 certificates, providing a concrete 
implementation and evaluation on IIoT-class hardware.
Benchmarking on a Raspberry Pi 4 platform shows that PQ-TLS 1.3 maintains handshake latency below 
15 ms and memory usage under 100 KB, with the primary overhead attributed to certificate size rather than 
cryptographic computation. The results confirm that Kyber-512 and Dilithium-2 are suitable for low-power 
sensors and edge controllers, while Kyber-1024 and Dilithium-5 provide stronger security for gateways with 
minimal latency impact. Furthermore, the paper offers sector-specific recommendations that align algorithm 
parameters with IIoT industry requirements.
The main limitations of this work include the use of a single hardware platform, controlled network 
conditions, and the absence of microcontroller-level and energy-consumption evaluations. These constraints 
will be addressed in future work through field testing on heterogeneous IIoT networks, hardware acceleration 
on FPGAs and embedded systems, and exploration of hybrid migration strategies combining classical and post-
quantum primitives.
In summary, PQ-TLS 1.3 using Kyber and Dilithium provides a viable pathway toward quantum-resistant 
authentication and key establishment in IIoT gateways. This study bridges theory and implementation, 
contributing a reproducible foundation for the secure migration of industrial infrastructures to the post-
quantum era.
Data availability
This study is based on the implementation and evaluation of post-quantum cryptographic protocols using pub-
licly available open-source libraries. The X.509 certificate generation was performed using liboqs version 0.8.0 
from the Open Quantum Safe project, while the TLS 1.3 integration utilized the Open Quantum Safe fork of 
WolfSSL version 5.6.3. As no experimental or proprietary datasets were generated or analyzed, there is no addi-
tional data associated with this work.
Received: 17 June 2025; Accepted: 10 November 2025
References
 1. National Academies of Sciences, E., Medicine et al. Quantum computing: progress and prospects. (2019).
 2. Shor, P . W . Introduction to quantum algorithms. Proc. Symp. Appl. Math. 58, 143–160 (2002).
 3. Post-quantum cryptography  CSRC  CSRC - csrc.nist.gov.  h t t p s :  / / c s r c  . n i s t .  g o v / p r  o j e c t  s / p o s t  - q u a n t  u m - c r y  p t o g r a p h y.
 4.  h t t p s :  / / c s r c  . n i s t .  g o v / N e  w s / 2 0  1 6 / P u b  l i c - K e  y - P o s t  - Q u a n  t u m - C r  y p t o g r  a p h i c -  A l g o r i t h m s.
 5. Federal Register : Request Access - federalregister.gov.  h t t p s :  / / w w w .  f e d e r a  l r e g i s  t e r . g  o v / d o c  u m e n t s  / 2 0 1 6 /  1 2 / 2 0  / 2 0 1 6 -  3 0 6 1 5 /  a n n o u 
n  c i n g -  r e q u e s  t - f o r -  n o m i n a  t i o n s  - f o r - p  u b l i c -  k e y - p o  s t - q u  a n t u m -  c r y p t o  g r a p h i  c - a l g o r i t h m s.
 6. NCCoE Migration to PQC Community of Interest Meeting  NCCoE -nccoe.nist.gov.  h t t p s :  / / w w w .  n c c o e .  n i s t . g  o v / g e  t - i n v o  l v e d / a  t 
t e n d -  e v e n t  s / n c c o  e - m i g r  a t i o n -  p q c - c  o m m u n i  t y - i n t  e r e s t -  m e e t i n g / p o s t - w e b i n a r - m a t e r i a l s (2023).
 7. NCCoE Migration to PQC Community of Interest Meeting  NCCoE - nccoe.nist.gov.  h t t p s :  / / w w w .  n c c o e .  n i s t . g  o v / g e  t - i n v o  l v e d / a  
t t e n d -  e v e n t  s / n c c o  e - m i g r  a t i o n -  p q c - c o m m u n i t y - i n t e r e s t - m e e t i n g (2023).
 8.  h t t p s :  / / w w w .  c i s a . g  o v / n e w  s - e v e  n t s / n e  w s / c i s  a - n s a -  a n d - n  i s t - p u  b l i s h -  n e w - r e  s o u r c  e - m i g r  a t i n g -  p o s t - q  u a n t u m - c r y p t o g r a p h y (2023).
 9. Three Draft FIPS for Post-Quantum Cryptography  CSRC - csrc.nist.gov.  h t t p s :  / / c s r c  . n i s t .  g o v / n e  w s / 2 0  2 3 / t h r  e e - d r a  ft  - fi  p  s - f o r  - p o 
s t -  q u a n t u  m - c r y p  t o g r a p h y (2023).
 10. Post-Quantum Cybersecurity Resources - nsa.gov.  h t t p s :  / / w w w .  n s a . g o  v / C y b e  r s e c u  r i t y / P  o s t - Q u  a n t u m -  C y b e r s e c u r i t y - R e s o u r c e s /.
 11. Tawfeeq, N. H., Y ousif, M., Al-Shareeda, M. A., Almaiah, M. & Shehab, R. Lightweight and quantum-resistant authentication for 
the Internet of Drones (IoD) using Dilithium signatures. Int. J. Innov. Res. Sci. Stud. https://doi.org/10.53894/ijirss.v8i2.5825 8(2), 
2842-2853 (2020).
 12. Samandari, J. & Gritti, C. Post-Quantum Authentication and Integrity in 3-Layer IoT Architectures. Conference on Privacy, Security 
and Trust https://doi.org/10.1109/PST62714.2024.10788057 (2024).
 13. Samandari, J. & Gritti, C. Post-Quantum Authentication in the MQTT Protocol. J. Cybersecur. Priv.  h t t p s : / / d o i . o r g / 1 0 . 3 3 9 0 / j c p 3 0 
3 0 0 2 1     (2023).
 14. Prajwal, C. P ., Mohan, A. S., Reddy, D. N. & Nimmy, K. Quantum-Safe Authentication Protocol leveraging qPUF for Industrial 
Internet of Things. Int. Conf. on Comput. Commun. Netw. Technol. https://doi.org/10.1109/ICCCNT61001.2024.10725580 (2024).
 15. Kumari, S., Singh, M., Singh, R. & Tewari, H. A post-quantum lattice based lightweight authentication and code-based hybrid 
encryption scheme for IoT devices. Comput. Networks https://doi.org/10.1016/j.comnet.2022.109327 (2022).
 16. Gupta, D. S. Pilike: Post-Quantum identity-based lightweight authenticated key exchange protocol for IIoT environments. IEEE 
Syst. J. https://doi.org/10.1109/JSYST.2023.3335217 (2024).
 17. McLoughlin, C., Gritti, C. & Samandari, J. Full Post-Quantum Datagram TLS Handshake in the Internet of Things. International 
Conference on Codes, Cryptology, and Information Security https://doi.org/10.1007/978-3-031-33017-9_4 (2023).
 18. Schöffel, M., Lauer, F ., Rheinländer, C. & Wehn, N. Secure IoT in the Era of Quantum computers-where are the bottlenecks? Italian 
Natl. Conf. on Sensors https://doi.org/10.3390/s22072484 (2022).
 19. Banegas, G., Zandberg, K., Herrmann, A., Baccelli, E. & Smith, B. A. Quantum-Resistant Security for Software Updates on Low-
power Networked Embedded Devices. IACR Cryptology ePrint Archive (2021).
 20. Behnia, R. & Y avuz, A. Towards practical post-quantum signatures for resource-limited Internet of Things. Asia-PacificComput. 
Syst. Archit. Conf. https://doi.org/10.1145/3485832.3488023 (2021).
 21. Sikeridis, D., Kampanakis, P . & Devetsikiotis, M. Post-quantum authentication in tls 1.3: a performance study. Cryptology ePrint 
Archive (2020).
 22. Dharminder, D. & Mishra, D. Lcppa: Lattice-based conditional privacy preserving authentication in vehicular communication. 
Trans. Emerg. Telecommun. Technol. 31, e3810 (2020).
 23. Paul, S. & Guerin, E. Hybrid opc ua: enabling post-quantum security for the industrial internet of things. In 2020 25th IEEE 
International Conference on Emerging Technologies and Factory Automation (ETFA), vol. 1, 238–245 (IEEE, 2020).
Scientific Reports |         (2026) 16:9582 20| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 21

24. Ravi, P ., Sundar, V .  K., Chattopadhyay, A., Bhasin, S. & Easwaran, A. Authentication protocol for secure automotive systems: 
Benchmarking post-quantum cryptography. In 2020 IEEE International Symposium on Circuits and Systems (ISCAS) 1–5 (IEEE, 
2020).
 25. Paul, S., Kuzovkova, Y ., Lahr, N. & Niederhagen, R. Mixed certificate chains for the transition to post-quantum authentication in 
tls 1.3. In Proceedings of the 2022 ACM on Asia Conference on Computer and Communications Security 727–740 (2022).
 26. Wang, F ., Wang, J. & Y ang, W . Efficient incremental authentication for the updated data in fog computing. Future Gener. Comput. 
Syst. 114, 130–137 (2021).
 27. Tang, Y ., Ba, Y ., Li, L., Wang, X. & Y an, X. Lattice-based public-key encryption with conjunctive keyword search in multi-user 
setting for iiot. Clut. Comput. 25, 2305–2316 (2022).
 28. Liu, J. et al. A post quantum secure multi-party collaborative signature with deterability in the industrial internet of things. Future 
Gener. Comput. Syst. 141, 663–676 (2023).
 29. Lohachab, A. et al. Using quantum key distribution and ecc for secure inter-device authentication and communication in iot 
infrastructure. In Proceedings of 3rd International Conference on Internet of Things and Connected Technologies (ICIoTCT) 26–27 
(2018).
 30. Latif, M. K., Jacinto, H. S., Daoud, L. & Rafla, N. Optimization of a quantum-secure sponge-based hash message authentication 
protocol. In 2018 IEEE 61st International Midwest Symposium on Circuits and Systems (MWSCAS) 984–987 (IEEE, 2018).
 31. Crockett, E., Paquin, C. & Stebila, D. Prototyping post-quantum and hybrid key exchange and authentication in tls and ssh. 
Cryptology ePrint Archive (2019).
 32. Chikouche, N., Cayrel, P .-L., Mboup, E. H. M. & Boidje, B. O. A privacy-preserving code-based authentication protocol for internet 
of things. J. Supercomput. 75, 8231–8261 (2019).
 33. Fujioka, A., Takashima, K., Terada, S. & Y oneyama, K. Supersingular isogeny diffie-hellman authenticated key exchange. In 
Information Security and Cryptology-ICISC 2018: 21st International Conference, Seoul, South Korea , November 28–30, 2018, 
Revised Selected Papers 21, 177–195 (Springer, 2019).
 34. Zhang, X., Xu, C., Wang, H., Zhang, Y . & Wang, S. Fs-peks: Lattice-based forward secure public-key encryption with keyword 
search for cloud-assisted industrial internet of things. IEEE Trans. Dependable Secure Comput. 18, 1019–1032 (2019).
 35. Round 1 Submissions - Post-Quantum Cryptography  CSRC  CSRC - csrc.nist.gov.  h t t p s :   /  / c s r  c . n i s  t . g  o v /  P r o j e c   t s / p  o  s t - q u a  n  t u m 
-  c r y p t  o g r  a p h  y /  p o s  t - q u  a  n t u m - c  r y p t o g   r a p h y  - s t a n d  a r d i  z a t i o n  /  r o u n d - 1 - s u b m i s s i o n s.
 36. Bos, J. et al. Crystals-kyber: a cca-secure module-lattice-based kem. In 2018 IEEE European Symposium on Security and Privacy 
(EuroS &P) 353–367 (IEEE, 2018).
 37. Ducas, L. et al. Crystals-dilithium: Digital signatures from module lattices. (2018).
 38. Tasopoulos, G. et al. Performance evaluation of post-quantum tls 1.3 on resource-constrained embedded systems. In International 
Conference on Information Security Practice and Experience 432–451 (Springer, 2022).
 39. Tasopoulos, G. et al. Energy consumption evaluation of post-quantum tls 1.3 for resource-constrained embedded devices. 
Cryptology ePrint Archive (2023).
 40. Chaudhary, D. et al. Anonymous quantum safe construction of three party authentication and key agreement protocol for mobile 
devices. IEEE Access 12, 74572–74585 (2024).
 41. Kumar, U., Garg, M., Kumari, S. & Dharminder, D. A construction of post quantum secure and signal leakage resistant authenticated 
key agreement protocol for mobile communication. Trans. Emerg. Telecommun. Technol. 34, e4695 (2022).
 42. Kumar, U., Garg, M. & Chaudhary, D. Design and analysis of a post-quantum secure three party authenticated key agreement 
protocol based on ring learning with error for mobile device. J. Supercomput. 81, 9 (2024).
Author contributions
- Abdul Basit Shahid and Khwaja Mansoor were primarily responsible for drafting the main body of the manu-
script, including the formulation of the core content, background, and literature review. - Y awar Abbas Bangash 
and Waseem Iqbal contributed significantly to the design and development of the proposed model and meth -
odology. In addition to this, Y awar Abbas Bangash also oversaw the overall project management, coordination 
among team members, and integration of contributions across sections. - Shynar Mussiraliyeva provided critical 
feedback, performed thorough proofreading, and actively supported the structural revisions and improvements 
throughout the manuscript. - All authors reviewed and approved the final version of the manuscript and agree 
to be accountable for all aspects of the work.
Funding
This research was supported by Sunway University, Malaysia. The authors gratefully acknowledge the institu -
tion’s support in facilitating this work.
Declarations
Competing interests
The authors decalre no competing interests.
Additional information
Correspondence and requests for materials should be addressed to Y .A.B.
Reprints and permissions information is available at www.nature.com/reprints.
Publisher’s note Springer Nature remains neutral with regard to jurisdictional claims in published maps and 
institutional affiliations.
Scientific Reports |         (2026) 16:9582 21| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/


---

## Page 22

Open Access  This article is licensed under a Creative Commons Attribution-NonCommercial-NoDerivatives 
4.0 International License, which permits any non-commercial use, sharing, distribution and reproduction in 
any medium or format, as long as you give appropriate credit to the original author(s) and the source, provide 
a link to the Creative Commons licence, and indicate if you modified the licensed material. Y ou do not have 
permission under this licence to share adapted material derived from this article or parts of it. The images or 
other third party material in this article are included in the article’s Creative Commons licence, unless indicated 
otherwise in a credit line to the material. If material is not included in the article’s Creative Commons licence 
and your intended use is not permitted by statutory regulation or exceeds the permitted use, you will need to 
obtain permission directly from the copyright holder. To view a copy of this licence, visit  h t t p : / / c r e a t i v e c o m m o 
n s . o r g / l i c e n s e s / b y - n c - n d / 4 . 0 /     .  
© The Author(s) 2025 
Scientific Reports |         (2026) 16:9582 22| https://doi.org/10.1038/s41598-025-28413-8
www.nature.com/scientificreports/

