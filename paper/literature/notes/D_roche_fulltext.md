# ROCHE: A Robust and End-to-End Privacy-Preserving Federated Learning Framework for Intrusion Detection in Industrial Internet of Things

- **Paper ID:** D
- **DOI:** https://doi.org/10.1109/jiot.2025.3612944
- **Source PDF:** `../pdf/ROCHE_A_Robust_and_End-to-End_Privacy-Preserving_Federated_Learning_Framework_for_Intrusion_Detection_in_Industrial_Internet_of_Things_paper_D.pdf`
- **Pages:** 21
- **Extracted:** auto via pypdf (layout/OCR not perfect; figures are not images)



---

## Page 1

IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025 52357
ROCHE: A Robust and End-to-End
Privacy-Preserving Federated Learning Framework
for Intrusion Detection in Industrial
Internet of Things
Imtiaz Ali Soomro
 , Member, IEEE, Hamood ur Rehman, Syed Jawad Hussain
 ,
Sohaib Latif
 , Senior Member, IEEE, Hana Mujlid
 , Member, IEEE, Syed Muhammad Mohsin
 ,
and Carsten Maple
Abstract—The Industrial Internet of Things (IIoT) has revo-
lutionized industrial automation, enabling real-time monitoring
and intelligent decision-making. However, the increasing connec-
tivity of IIoT devices exposes them to cyber threats, necessitating
robust intrusion detection systems (IDSs). Traditional centralized
IDS solutions face concerns regarding the sharing of sensitive
data, high computational costs, and communication overhead.
Federated learning (FL) provides a privacy-preserving alternative
to such centralized systems. However, existing FL-based IDS
frameworks may face challenges such as high resource con-
sumption and privacy threats, such as gradient leakage from
shared updates. To address these challenges, we propose robust
optimization for encrypted FL (ROCHE), a lightweight FL-based
IDS optimized for IIoT, which ensures data privacy and eﬃciency.
ROCHE uses low-degree polynomial approximations to replace
complex activation functions (AFs), reducing computational load
without signiﬁcantly impacting accuracy. An adaptive quanti-
zation mechanism is utilized to reduce bandwidth consumption
while ensuring accurate model convergence. To preserve data
privacy during model aggregation, ROCHE integrates symmetric
homomorphic encryption (HE), enabling secure model updates
while maintaining resilience to user dropout. Comprehensive
security analysis and experiments demonstrate that ROCHE out-
performs state-of-the-art frameworks. Compared with MiTFed,
ROCHE reduces computational overhead by 11% and lowers
Received 17 April 2025; revised 14 August 2025; accepted 6 Septem-
ber 2025. Date of publication 22 September 2025; date of current
version 8 December 2025. This work was supported by the UK
Research and Innovation (UKRI) through the Academic Centre of Excel-
lence in Cyber Security Research, University of Warwick, under Grant
EP/R007195/1, and through the National Hub for Edge AI under
Grant EP /Y028813/1. (Corresponding authors: Syed Muhammad Mohsin;
Carsten Maple.)
Imtiaz Ali Soomro and Syed Jawad Hussain are with the Sir
Syed CASE Institute of Technology, Islamabad 44000, Pakistan (e-mail:
imtiaz.soomro@case.edu.pk; jawad.hussain@case.edu.pk).
Hamood ur Rehman is with the Department of ECE, Habib University,
Karachi 75350, Pakistan (e-mail: hamood.rehman@sse.habib.edu.pk).
Sohaib Latif is with the Department of Computer Science and Soft-
ware Engineering, Grand Asian University, Sialkot 51040, Pakistan (e-mail:
sohaib.latif@gaus.edu.pk).
Hana Mujlid is with the Department of Computer Engineering, Taif
University, Taif 21944, Saudi Arabia (e-mail: hmujlid@tu.edu.sa).
Syed Muhammad Mohsin is with the Department of Com-
puter Science, University of Wah, Wah Cantt 47040, Pakistan
(e-mail: syedmmohsin9@gmail.com).
Carsten Maple is with the Cyber Security Centre, University of Warwick,
CV4 7AL Coventry, U.K. (e-mail: cm@warwick.ac.uk).
Digital Object Identiﬁer 10.1109 /JIOT.2025.3612944
communication cost by 16%, demonstrating its e ﬃciency in
optimizing resource utilization while maintaining robust privacy
preservation in FL-based IDS. In addition, ROCHE maintains
an average accuracy of over 90% across multiple attack types.
Deployment in a cloud-based IIoT environment demonstrates its
feasibility, establishing ROCHE as a scalable and e ﬃcient IDS
for IIoT security.
Index Terms —Adaptive quantization, data privacy, dynamic
Chebyshev optimization (DCO), homomorphic encryption (HE),
intrusion detection system (IDS), privacy-preserving federated
learning (PPFL).
I. I NTRODUCTION
W
ITH the rapid proliferation of smart devices and
next-generation network technologies, the Internet of
Things (IoT) has emerged as a transformative paradigm,
interconnecting a vast ecosystem of heterogeneous devices [1],
[2]. The integration of IoT into industrial systems, commonly
referred to as Industrial IoT (IIoT) [3], [4], enables intelligent
automation and real-time monitoring of industrial processes
through seamless connectivity. IIoT environments generate
massive amounts of sensitive data, which, when transmitted
over the Internet, can be susceptible to cyber threats, including
data breaches, unauthorized access, and network intrusions
[5], [6]. These attacks can have severe consequences, such as
data manipulation, disruption of critical operations, and denial-
of-service (DoS) attacks. By 2026, 23 billion connected IoT
devices are projected, highlighting both new security chal-
lenges and signiﬁcant market opportunities for IoT security
solutions [7].
Intrusion detection systems (IDSs) have been developed to
identify malicious activities within network tra ﬃc. Traditional
IDSs are based on centralized machine learning (ML) models,
which require continuous monitoring and data collection from
distributed IIoT devices. However, centralizing sensitive data
poses signiﬁcant privacy risks and communication overhead
[8]. To address these concerns, federated learning (FL) [9] has
emerged as a privacy-preserving decentralized ML paradigm
that enables collaborative model training while ensuring data
remains on local systems. FL has garnered signiﬁcant interest
from both academia and industry as a secure and robust
2327-4662 © 2025 IEEE. All rights reserved, including rights for text and data mining, and training of artiﬁcial intelligence and
similar technologies. Personal use is permitted, but republication /redistribution requires IEEE permission.
See https://www.ieee.org/publications/rights/index.html for more information.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 2

52358 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
Fig. 1. FL-based IDS in a smart factory environment.
framework for IIoT networks. Fig. 1 illustrates an FL-based
collaborative IDS deployed in a smart factory environment.
In this framework, a network-based gateway captures tra ﬃc
from IIoT devices and performs local intrusion detection. The
locally trained models are then transmitted to a federation
entity, which aggregates updates from multiple nodes to iter-
atively reﬁne the global model. This decentralized approach
enhances privacy by keeping sensitive data localized and
improves scalability by distributing computational tasks across
devices. As a result, FL emerges as a highly promising solution
for securing IIoT environments.
However, despite its advantages, FL-based IDSs face several
key challenges, including data leakage, high communication
overhead, nonindependent and identically distributed (non-
IID) data distributions, and class imbalance in attack patterns
[10]. Privacy threats such as gradient inversion and model
extraction attacks can compromise the conﬁdentiality of
locally trained models [11], [12], [13]. In addition, the frequent
exchange of model updates between IIoT devices and the
aggregation server results in excessive bandwidth consump-
tion, which is particularly problematic in resource-constrained
IIoT environments. Moreover, the inherent heterogeneity of
IIoT data further complicates the global model’s convergence,
leading to performance degradation.
Addressing these challenges requires an integrated approach
that simultaneously enhances privacy, communication e ﬃ-
ciency, and model performance in FL-based IDSs. Sec-
tions I-A–I-C explore these challenges in detail and outline
potential solutions to develop a scalable, secure, and e ﬃcient
FL framework for IIoT IDS.
A. Privacy Concern and Communication Overhead in FL
FL can introduce privacy and communication challenges
due to its distributed nature and the frequent aggregation
mechanism of the model [14], [15], [16], [17]. Although
FL mitigates privacy risks associated with centralized data
aggregation, it remains susceptible to sophisticated privacy
attacks that can reconstruct sensitive information during the
exchange of model updates [18].
From a security perspective, adversarial attacks such as
DeepLeakage [19] can reconstruct private training data from
exposed gradients, posing a serious threat to data conﬁdential-
ity. Although secure aggregation (SA) [20] has been proposed
to protect individual updates, it remains vulnerable to model
extraction attacks [21], [22], where an attacker can infer
sensitive details from the aggregated global model. In addition,
non-IID data distributions in IIoT networks exacerbate security
risks by creating discrepancies in model updates, making cer-
tain client contributions more susceptible to inference attacks.
From a communication e ﬃciency perspective, frequent
model updates require substantial bandwidth, leading to
excessive communication overhead. For instance, a single
transmission of model gradients from a GPT-3 model can
require up to 2.8 TB of data [16], rendering FL impracti-
cal in bandwidth-constrained IIoT environments. Furthermore,
data imbalance in IIoT networks—where attack instances
are underrepresented—compounds the challenge by skewing
model convergence, necessitating additional communication
rounds and further increasing overhead.
Existing research has focused on addressing these chal-
lenges through privacy-preserving techniques such as di ﬀer-
ential privacy (DP) [23], [24], homomorphic encryption (HE)
[25], [26], and multiparty computation (MPC) [27], [28],
[29]. In addition, methods such as quantization [30], [31],
compression [32], [33], and client scheduling [34], [35] have
been proposed to reduce communication overhead. However,
these techniques often introduce tradeo ﬀs, such as accuracy
loss and increased computational complexity, limiting their
practical applicability in IIoT settings.
To overcome these limitations, there is a growing need for
integrated solutions that enhance both security and commu-
nication eﬃciency without compromising model performance.
This necessitates the development of novel frameworks that
leverage adaptive learning mechanisms, secure computation,
and optimized communication protocols to facilitate scalable
and privacy-preserving FL (PPFL)-based IDSs in IIoT envi-
ronments.
B. Motivation
FL has emerged as a promising paradigm for decentralized
model training, enabling collaborative learning while mitigat-
ing privacy risks associated with centralized data aggregation
by avoiding direct data sharing.
A key challenge in FL systems is the risk of privacy
breaches due to attacks such as gradient inversion and plaintext
inference [11], [12], [13]. While SA schemes [20] enhance
privacy by obfuscating individual updates, they remain vul-
nerable to model extraction attacks [21], [22] that exploit the
global model to infer sensitive information. Furthermore, FL
suﬀers from signiﬁcant communication overhead, as frequent
model updates exchanged between clients and the central
server consume substantial bandwidth and energy resources.
This tradeo ﬀ among security, communication e ﬃciency, and
model accuracy is particularly critical in constrained IIoT
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 3

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52359
environments, where optimizing all three factors is essential
for practical deployment.
One promising approach to mitigating privacy risks in FL
is the use of HE, which enables computations on encrypted
data. However, applying HE to deep learning models presents
challenges due to the nonlinear nature of neural network
(NN) activation functions (AFs). To address this, various tech-
niques such as power function approximations [36], lookup
tables [37], and polynomial approximations [38], [39] have
been explored. Despite these advancements, existing methods
often introduce excessive computational overhead and fail to
generalize across diverse datasets, limiting their practicality
in real-world IIoT deployments. In addition, FL participants
typically possess non-IID data, leading to skewed global model
performance. While prior research [40], [41], [42], [43], [44],
[45] has attempted to address non-IID challenges, most studies
focus solely on convergence and ignore crucial auxiliary
metrics such as accuracy and F1-score, which provide deeper
insights into data heterogeneity and model robustness.
Data imbalance further exacerbates these issues, as attack
instances are often underrepresented in comparison to benign
data. Conventional loss functions, including cross-entropy
loss [46] and focal loss [47], struggle to optimize perfor-
mance under such conditions. Moreover, FL-based systems
remain vulnerable to poisoning attacks, which compromise
the integrity of the global model and reduce IDS e ﬃcacy.
Overcoming these limitations requires advanced techniques
that integrate secure computation, communication e ﬃciency,
and adaptive learning mechanisms to develop robust, scalable,
and eﬃcient IDS solutions for IIoT ecosystems.
To address these pressing challenges, this research focuses
on designing a secure and communication-e ﬃcient FL-based
IDS with provable performance guarantees. Speciﬁcally, the
goal is to answer the following research questions (RQs).
RQ1: How can FL mitigate privacy risks (e.g., gradient
inversion attacks) while minimizing communication overhead
in resource-constrained IIoT environments?
RQ2: Can a model be developed that balances security, com-
munication e ﬃciency, and model accuracy while addressing
device heterogeneity and non-IID data distributions in FL-
based IDS?
C. Key Contributions
This research introduces robust optimization for encrypted
FL (ROCHE), a secure and e ﬃcient FL framework designed
to address critical challenges in PPFL for resource-constrained
IIoT environments. ROCHE integrates security, communica-
tion e ﬃciency, and model accuracy into a uniﬁed solution,
oﬀering provable performance guarantees. The key contribu-
tions of this work are as follows.
1) ROCHE replaces traditional AFs with low-degree
Chebyshev polynomial approximations, enabling e ﬃ-
cient HE-based computation. To enable e ﬃcient
encrypted computation, ROCHE employs low-degree
Chebyshev polynomial approximations, signiﬁcantly
reducing computational complexity while maintaining
high accuracy in both training and inference. This
approach improves HE-based model evaluation without
introducing excessive overhead.
2) To minimize communication overhead, ROCHE intro-
duces a dynamic quantization mechanism, where edge
devices adjust quantization levels based on available
bandwidth and computational resources. Unlike ﬁxed
quantization strategies, this adaptive technique ensures
that model updates retain critical information while
reducing transmission size, making FL feasible in
bandwidth-constrained IIoT environments. Experimental
results demonstrate that this approach reduces commu-
nication costs by 12% while preserving model accuracy
within 97% of the uncompressed model.
3) A novel SA scheme is proposed, which combines sym-
metric HE with a secret-sharing technique that allows
additive operations on encrypted data, ensuring privacy
during the aggregation process. In addition, the scheme
supports robustness to client dropouts, preventing any
single point of failure while preserving privacy without
exposing the private keys of dropped devices.
4) A comprehensive security analysis is conducted to val-
idate ROCHE’s resilience against gradient inversion
attacks and model extraction attacks. Benchmarking
against existing PPFL frameworks demonstrates that
ROCHE achieves superior communication e ﬃciency,
fault tolerance, and privacy preservation while maintain-
ing competitive accuracy.
5) To demonstrate practical feasibility, ROCHE is imple-
mented and validated in a cloud-based IIoT IDS.
Extensive experiments on real-world network intrusion
datasets conﬁrm that ROCHE delivers high detec-
tion accuracy, reduced communication overhead, and
enhanced privacy preservation, making it a scalable and
robust solution for IIoT security applications.
The remainder of this article is organized as follows.
Section II reviews the related work on FL-based IDS and
privacy-preserving techniques. Threat model, problem formu-
lation, and proposed system model are described in Section III.
Security analysis of masking mechanism and the HE scheme
are described in Section IV, and performance analysis of
client’s and server’s computation and communication costs
is given in Section V. Experimental setup, dataset, and
evaluation metrics are discussed in Section VI. Results and
comparative analysis are elaborated in Section VII. Finally,
Section VIII concludes this study with a conclusion and future
work.
II. L ITERATURE REVIEW
A. IDSs in Industrial Cyber-Physical Systems (ICPSs)
ICPS integrates computational and physical components
to enhance automation, control, and monitoring processes in
industries such as manufacturing, energy, and transportation.
These systems rely on interconnected sensors, actuators, and
communication networks to function e ﬃciently. However, the
reliance on interconnected IoT devices exposes ICPS to var-
ious security vulnerabilities, including malware attacks, data
breaches, and unauthorized access [48], [49].
To mitigate these threats, IDS has been extensively
employed. IDS monitors network tra ﬃc and device behavior
to identify malicious activities and prevent potential disrup-
tions. Traditional IDS methods rely heavily on signature-based
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 4

52360 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
or anomaly-based detection techniques. Signature-based IDS
detects known attack patterns but struggles to identify zero-
day attacks, while anomaly-based systems ﬂag deviations from
normal behavior but often result in high false-positive (FP)
rates [50]. In ICPS, these limitations necessitate advanced
IDS solutions tailored to the unique requirements of industrial
environments, such as real-time detection, scalability, and
resource eﬃciency.
B. ML in IDS for IIoT
ML has signiﬁcantly enhanced the capabilities of IDS by
enabling the detection of complex attack patterns. Supervised
learning models, such as support vector machines (SVMs) and
NNs, have been widely used to classify malicious activities
[51]. In addition, unsupervised learning methods, such as
clustering and anomaly detection, help to identify previously
unseen threats. For instance, deep learning techniques like con-
volutional NN (CNN) and RNN have demonstrated remarkable
performance in processing large volumes of network data and
identifying sophisticated attack vectors [52].
Recent studies also explore hybrid approaches combin-
ing supervised and unsupervised techniques to improve
detection accuracy. Hybrid models leverage the strengths
of both paradigms, enabling enhanced adaptability to
dynamic attack patterns in ICPS environments [53]. However,
these models demand signiﬁcant computational resources,
which can be a challenge for IoT devices in industrial
settings.
Despite these advancements, applying ML in ICPS faces
several challenges. Centralized ML models require data aggre-
gation, which can compromise privacy and introduce latency.
Furthermore, the computational complexity of ML models,
especially deep learning architectures, poses challenges for
resource-constrained IoT devices commonly found in ICPS
[54]. These challenges underscore the need for distributed and
privacy-preserving ML approaches.
C. FL-Based IDS
FL has emerged as a promising solution to address the limi-
tations of centralized ML in ICPS. FL allows multiple devices
to collaboratively train a global model without sharing raw
data, thus preserving privacy and reducing data transmission
costs [20]. In FL, each device trains a local model using its
data and shares only the model updates with a central server
for aggregation. This decentralized approach is particularly
suited for ICPS, where data are distributed across multiple
devices and privacy is a critical concern.
Chhikara et al. [55] proposed an adaptive vertical FL (VFL)
framework incorporating DP with ML models such as SVMs,
k-nearest neighbors (kNNs), multilayer perceptron (MLP), and
random forest. Li et al. [46], [56] employed CNNs with
dynamic weighted averaging FL and DeepFed, respectively, as
their frameworks and privacy-preserving mechanisms (PPMs).
Similarly, Abdel-Basset et al. [57] integrated encoding with
FL, while Aouedi and Piamrat [58] applied model blending
with FL as a PPM.
A novel approach, FEILDS, is introduced in [59], lever-
aging trustworthy FL-based aggregation algorithms. In [60],
FL-based mimic learning is explored as a unique PPM for
IDS. In addition, generative adversarial networks (GANs) are
incorporated with FL and DP in [61] and [62], respectively.
Several studies, including [15], [63], [64], and [65], rely
solely on FL as a PPM, implementing frameworks such as
F-AL-Based-IoV-IDS, IDS for IIoT, IDS for IoT, and DPA-FL-
poisoning-attack-defense. A PPFL aggregation scheme based
on secret sharing to protect local model updates while ensuring
Byzantine robustness is proposed by Mei et al. [66]. Their
approach e ﬀectively mitigates poisoning attacks in FL, even
when malicious clients form a majority. The study introduces
SA mechanisms leveraging cosine and Euclidean distance
calculations to ﬁlter out malicious model updates and maintain
model integrity.
Manh et al. [67] applied HE in FL-based intrusion detec-
tion for Internet of Vehicles (IoV) networks, where resource
constraints pose challenges for local model training. Their
framework enables secure o ﬄoading of encrypted data to a
centralized server, allowing direct computation on encrypted
ciphertexts. They utilize the CKKS encryption scheme, which
performs approximate arithmetic over real numbers ( R) and
inherently introduces approximation errors during computa-
tions. Despite this, by leveraging SIMD-based optimization,
the framework achieves intrusion detection performance com-
parable to unencrypted methods, with an accuracy gap of less
than 0.8%.
Abou El Houda et al. [68] introduced MiTFed, an FL-based
collaborative attack mitigation framework leveraging software-
deﬁned networking (SDN) and blockchain. The framework
ensures privacy-preserving IDS through secure MPC (SMPC)
and Ethereum smart contracts, enabling distributed SDN
domains to train a shared IDS model without exposing
sensitive data. Their evaluation on the NSL-KDD dataset
demonstrates high detection accuracy for DDoS and zero-day
attacks, surpassing traditional ML-based IDS solutions.
HE has also been applied in various forms. Speciﬁcally,
Verma et al. [69] utilized HE with Paillier-based encryption,
Albaseer and Abdallah [70] combined CKKS-based HE with
SMPC, and Ma et al. [71] employed a two-trapdoor HE
mechanism with Byzantine-tolerant aggregation.
While advanced privacy-preserving techniques, such as
secret sharing, HE, and SMPC, have demonstrated e ﬀec-
tiveness in FL-based intrusion detection, they can introduce
signiﬁcant challenges. One of the primary concerns is the
computational overhead introduced by these techniques, which
makes them impractical for resource-constrained IIoT devices.
Similarly, although communication-e ﬃcient strategies like
quantization and compression help to reduce bandwidth con-
sumption, they often lead to model accuracy degradation,
particularly in non-IID data settings where local datasets di ﬀer
signiﬁcantly across devices.
Table I summarizes and compares the proposed ROCHE
with key FL-based IDS frameworks in terms of encryption
method, quantization strategy, dropout tolerance, non-IID data
support, datasets used, and accuracy (%). This comparison
helps to clearly deﬁne the status of ROCHE in the broader
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 5

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52361
TABLE I
COMPARATIVE ANALYSIS OF OUR PROPOSED ROCHE W ITH KEY FL-B ASED IDS F RAMEWORKS
research landscape and illustrates its superior performance in
terms of accuracy, privacy preservation, and communication
eﬃciency.
III. T HREAT MODEL , P ROBLEM FORMULATION , AND
PROPOSED SYSTEM MODEL
A. Threat Model
This study focuses on cyber threats against IIoT systems and
the potential security vulnerabilities and privacy breaches in
FL. The primary concern in IIoT environments is the presence
of malicious entities that can compromise the security and
privacy of the FL process. We consider the following threat
scenarios.
1) Malicious Cloud Server: The cloud server, responsible
for aggregating model updates, is considered honest-but-
curious, meaning it follows the protocol correctly but may
attempt to extract sensitive information from the received
updates. This makes the system vulnerable to various attacks,
such as poisoning attacks, where the server manipulates the
aggregated model to mislead participating devices into accept-
ing a compromised global model, and eavesdropping, where
the server intercepts and analyzes model updates to infer
private data from devices.
2) External Adversaries: Beyond threats from the cloud
server, external adversaries may also pose security risks
by attempting to intercept communications, where attackers
eavesdrop on data exchanged between devices and the server
to steal sensitive information, or by launching DoS attacks,
which disrupt the FL process by overwhelming the network
or participating devices, preventing normal operation.
3) Attack Scenarios: In addition to threats posed by the
honest-but-curious cloud server and external adversaries, vari-
ous attack scenarios can compromise the security and integrity
of FL in IIoT environments. We focus on the following key
attack scenarios.
1) Reconnaissance Attack: Adversaries collect basic details
about the system, such as network architecture and
device models, to plan further attacks.
2) Response Injection Attack: Adversaries fabricate
response messages to provide false information about
the system state, interfering with monitoring and control
processes.
3) Command Injection Attack: Adversaries inject false
control commands to manipulate device behavior and
disrupt industrial processes.
4) DoS Attack: Adversaries overwhelm the network or
devices with excessive tra ﬃc, preventing them from
oﬀering standard services.
5) Eavesdropping Attack: Adversaries intercept and ana-
lyze communication between devices and the server to
infer sensitive information.
6) Forged Aggregation Attack:The malicious central server
tampers with the aggregated model to mislead devices
into accepting a ﬂawed global model.
B. Problem Formulation
FL in IIoT environments faces signiﬁcant security and pri-
vacy challenges due to both honest-but-curious cloud servers
and external adversaries. The cloud server, while following the
FL protocol, may attempt to infer sensitive information from
model updates or manipulate the aggregated model through
forged aggregation attacks. In addition, external attackers can
disrupt the system through eavesdropping, DoS attacks, or
command injection, among other threats. These vulnerabilities
compromise the reliability of IDS, which play a crucial role
in safeguarding IIoT networks from cyber threats.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 6

52362 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
1) Objective: The objective of this study is to develop a
privacy-preserving and secure FL-based IDS that mitigates
these risks while ensuring high detection accuracy and com-
putational e ﬃciency. This requires designing robust defense
mechanisms to protect model updates, prevent adversarial
manipulation, and enhance resilience against both internal and
external threats.
2) Constraints: Devices in IIoT environments have lim-
ited computational and communication resources, making it
challenging to perform complex operations e ﬃciently. In
addition, the central server is assumed to be honest-but-
curious, meaning it follows the protocol but may attempt to
infer sensitive information from model updates. Furthermore,
the IDS must operate in real time to promptly detect and
respond to cyber threats, ensuring minimal latency in detecting
malicious activities.
3) Time Overhead: In an FL framework, the duration
of each iteration on the device side is primarily inﬂuenced
by three factors: encryption, decryption, and model training.
Approximately 20% of this time is dedicated to data transmis-
sion and waiting for the aggregated model parameters to be
sent back from the central server [72]. Devices cannot progress
to the next iteration until they receive the updated global
model from the server. On the server side, synchronization
barriers create challenges due to the heterogeneity in device
resources and data distributions. This heterogeneity often leads
to varying response times between devices, a common problem
called the straggler problem [73]. If we represent the response
time of device Di as Ri, the server’s waiting delay can be
expressed as shown in the following equation:
Rserver = max
 
R1, R2, R3,..., R|D|

. (1)
This formula shows that the server’s waiting delay in each
round is determined by the slowest device, Dslowest. The server
must wait for Dslowest to complete its training before it can
perform model aggregation. As a result, the e ﬃciency of the
FL-based IDS is signiﬁcantly a ﬀected, requiring strategies to
mitigate these delays and improve real-time performance.
C. Proposed System Model
The proposed framework, ROCHE, is designed for IIoT
with a typical FL architecture. This architecture adopts a
client–server (CS) model, where multiple devices collabora-
tively train a global IDS model while maintaining local data
privacy
D ={d1, d2,..., dk}. (2)
Fig. 2 illustrates the system architecture of ROCHE, depict-
ing interactions among IoT devices, the central cloud server
(CC-server), and the registration authority (RA). Each IoT
device trains a local model on its private dataset without
exposing raw data, ensuring data privacy. The central server
securely aggregates encrypted model updates, reﬁning the
global model iteratively. The RA is responsible for initial-
izing system parameters and ensuring secure communication
between devices and the central server. Key components, such
Fig. 2. Workﬂow and components of the proposed ROCHE framework.
as dynamic Chebyshev optimization (DCO), adaptive quanti-
zation, and HE, are incorporated to enhance privacy, reduce
communication overhead, and improve model performance.
In this setup, a mobile edge network comprises an edge
server and a collection of distributed devices represented as:
D ={1, 2,..., N}. Each device i∈N is equipped with a single
antenna and possesses a local dataset Di of size|Di|. The data
are collected and stored locally on each device, ensuring data
privacy. The goal of the FL framework is to collaboratively
train a shared NN model for IDS across all devices without
sharing raw data. The local loss function for device i is deﬁned
in the following equation:
Fi (w) := 1
|Di|
|Di|X
j=1
f j (w) (3)
where w represents the model parameters and f j(w) is the loss
for data sample j. The global training objective is to minimize
the weighted sum of local losses that can be calculated using
the following equation:
min
w∈Rd
F (w) =
NX
i=1
piFi (w) (4)
where d is the total number of NN model parameters and pi
is the weight of device i, calculated as shown in the following
equation:
pi = |Di|PN
i=1|Di|
,
NX
i=1
pi = 1. (5)
Fig. 3 provides a detailed sequence diagram of the ROCHE
framework, illustrating the interactions between the RA, IoT
devices (clients), and the cloud server during the initialization,
aggregation, and veriﬁcation phases. The proposed ROCHE
framework for IIoT IDS consists of several key phases.
1) Initialization Phase: A RA generates and distributes
system parameters and public-private key pairs to IoT
devices and the cloud server. This ensures a secure
communication channel and sets up the foundation for
FL-based IDS.
2) Local Model Training on IoT Devices: The cloud server
initializes a global model W and distributes it to all
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 7

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52363
Fig. 3. Sequence diagram of the proposed ROCHE framework.
participating IoT devices. Each device di trains the
model using its private dataset PDk and updates its local
model. The local update for training round tr is given
by the following equation:
Wi
tr+1 = Wi
tr−
iX
e=0
 
ηtr∇Fi
 
Wi
tr,e, Xi
tr,e

(6)
where ηtr denotes the learning rate at iteration tr,∇Fi
represents the gradient of the loss function for device di,
e stands for the local training epochs, and Xi
tr is the local
training data. After training, each device di encrypts its
updated model gradients using HE before sending them
to the cloud server.
3) Encryption of Local Model Updates: To ensure data
privacy, each IoT device encrypts its local model updates
before transmitting them to the cloud server. This
prevents any unauthorized access to sensitive model
parameters.
4) Transmission of Encrypted Updates to the Cloud Server:
The cloud server collects the encrypted gradient updates
from all participating devices and performs SA. The
global model update at round tr is computed as shown
in the following equation:
Wtr = 1
Nk
kX
i=1
nkWi
tr (7)
where Nk represents the total number of data samples
across all devices and nk denotes the number of samples
held by device di. The central server S manages the
aggregation process, applies secure unmasking tech-
niques, and generates cryptographic proofs to verify the
correctness of the aggregation before distributing the
updated model.
5) Global Model Update and Distribution: The cloud
server updates the global IDS model based on the
aggregated parameters and redistributes it to all IoT
devices. This iterative process continues until the model
achieves convergence.
6) Veriﬁcation Phase: Before sharing the updated model,
the cloud server veriﬁes its integrity and correct-
Fig. 4. Architecture of a CNN with convolutional layers, pooling layers, and
fully connected layers leading to a classiﬁcation output.
ness using cryptographic validation techniques. This
ensures that the aggregated model remains unaltered and
resistant to adversarial modiﬁcations, maintaining the
security and reliability of the FL-based IDS.
This framework ensures privacy, security, and e ﬃciency in
ROCHE, making it well-suited for IIoT environments. The
core of our proposed solution ROCHE, a multilayered com-
munication paradigm, to achieve eﬃcient and secure FL-based
IDS in resource-constrained IoT environments, is elaborated
in the following.
1) Convolutional NN: A typical NN is a combination of
neurons arranged in layers. Each neuron receives input from
other neurons with an associated weight w and a bias b, as
shown in Fig. 4. It then uses (8) to compute some function f
on the weighted sum of its input. The output of this neuron is
given as input to other neurons
y = f
 3X
i=1
xiwi + b
!
. (8)
In (8), xi is the input, wi is the weight, b is the bias term,
and f is the AF. In this study, our focus is on CNNs, a deep
NN algorithm primarily used for attack vector classiﬁcation.
In CNN, each input passes through a series of layers during
the training and testing phases. These layers consist of con-
volutional layers (Conv), AFs, pooling layers, fully connected
(FC) layers, and a softmax layer [74].
Our proposed CNN consists of two convolutional layers
with ReLU AFs, two pooling operations, two fully connected
layers, and a softmax layer, as shown in Fig. 4.
D. Dynamic Chebyshev Optimization
DCO, a novel approach designed to enhance the e ﬃciency
and accuracy of polynomial approximations in PPFL, is dis-
cussed in the following. Traditional Chebyshev approximation
methods rely on ﬁxed intervals and coe ﬃcients, which may
not be optimal for heterogeneous IoT environments where
data distributions can vary signiﬁcantly across devices. DCO
addresses this limitation by dynamically adapting the approx-
imation process based on the input data distribution and
training dynamics, ensuring robust performance in diverse
scenarios.
The core innovation of DCO lies in its ability to dynamically
adjust the interval and coeﬃcients used for polynomial approx-
imation. Unlike traditional methods that use a ﬁxed interval
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 8

52364 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
[−1, 1], DCO determines the optimal interval [ a, b] based on
the statistical properties of the input data, such as the mean µ
and standard deviation σ. This interval is calculated as shown
in the following equation:
[a, b] =

µ− kσ,µ + kσ

(9)
where k is a scaling factor determined empirically or through
cross validation. By focusing on the most relevant range of
values, DCO ensures that the approximation is tailored to the
speciﬁc characteristics of the data, improving accuracy and
reducing computational complexity.
In addition to dynamic interval selection, DCO employs an
adaptive coe ﬃcient calculation mechanism. The Chebyshev
coeﬃcients ck are updated iteratively during the training pro-
cess to minimize the approximation error for the current batch
of data. This is achieved through a lightweight optimization
step integrated into the FL pipeline. The coe ﬃcients are
updated using a gradient-based optimization method, as shown
in the following equation:
c(t+1)
k = c(t)
k −η∂E (x)
∂ck
(10)
where η is the learning rate and E(x) is the approxima-
tion error. This adaptive process ensures that the polynomial
remains accurate even as the data distribution evolves over
time.
To further reﬁne the approximation, DCO incorporates an
error feedback mechanism. The approximation error E(x) is
calculated for each batch and used to iteratively improve the
polynomial. The error is minimized using a loss function that
balances accuracy and computational complexity, as shown in
the following equation:
L =
X
x∈batch
|E (x)| +λ· complexity (p (x)) (11)
where λ is a regularization parameter. This feedback loop
ensures that the polynomial approximation becomes increas-
ingly accurate over time, even in dynamic and heterogeneous
environments.
The mathematical formulation of DCO is based on the
Chebyshev polynomial series. Given a continuous function
f (x) deﬁned over the dynamically selected interval [a, b], DCO
expresses f (x) as shown in the following equation:
f (x) =
nX
k=0
ckTk (x), x∈ [a, b] (12)
where ck are the Chebyshev coe ﬃcients and Tk(x) are the
Chebyshev polynomials deﬁned by the recurrence relation, as
shown in the following equation:
Tn+1 (x) = 2xTn (x)− Tn−1 (x) (13)
with T0(x) = 1 and T1(x) = x. The coe ﬃcients ck are
calculated using the orthogonality property of Chebyshev
polynomials and are updated iteratively to minimize the
approximation error.
The advantages of DCO are manifold. First, it achieves
higher approximation accuracy compared with traditional
methods by dynamically adjusting the interval and coe ﬃcients
based on the input data distribution. Second, it reduces compu-
tational complexity by focusing the approximation on the most
relevant interval, minimizing the number of polynomial terms
required. Third, DCO is scalable and suitable for large IoT
networks with diverse data distributions and device capabili-
ties. Finally, DCO is fully compatible with HE, ensuring that
sensitive data remain encrypted throughout the computation,
thus preserving privacy.
E. Adaptive Quantization
Adaptive quantization (AQ), a novel technique designed
to address the communication overhead challenges in FL
for resource-constrained IIoT environments, is elaborated
here. Traditional FL frameworks transmit full-precision model
updates, which are ine ﬃcient in bandwidth-constrained set-
tings. To reduce communication overhead, we propose an
AQ scheme that allows devices to dynamically adjust their
quantization levels based on their available communication
resources, as shown in Algorithm 2. Unlike traditional quan-
tization methods that enforce a uniform strategy across all
devices, AQ accounts for device heterogeneity, enabling e ﬃ-
cient on-device training while maintaining model accuracy.
The AQ scheme employs a K-level quantizer, where K
represents the number of distinct values to which each weight
can be mapped. For each device i∈N , the model updates
xi are quantized to reduce their size before transmission. We
assume that the elements of xi fall within the range [ r1, r2].
The quantization process is deﬁned as follows.
1) The range [ r1, r2] is partitioned into N contiguous inter-
vals with equal probability.
2) The threshold value separating the lth and ( l + 1)th
intervals is given by the following equation:
T (l) = r1 + l· ∆N (14)
where ∆N is the quantization interval, calculated using
the following equation:
∆N = r2− r1
N− 1. (15)
Each weight xi(k) is mapped to a discrete value ¯ xi(k) using
the following stochastic quantization rule:
QN (xi (N))
=
(
T (l + 1), with probability xi(N)−T(l)
T(l+1)−T(l)
T (l), otherwise.
This rule assigns xi(N) to the quantization level T(l + 1) with
a probability proportional to its distance from T(l), ensuring
minimal distortion. The quantized output ¯xi(N) takes a discrete
value from the set as shown in the following equation:
{r1, r1 + ∆N, r1 + 2∆N,..., r2− ∆N, r2}. (16)
The key novelty of AQ lies in its ability to dynamically
adjust the quantization levels based on the communication
resources of each device. Devices with limited bandwidth
can use fewer quantization levels (smaller N), while devices
with higher bandwidth can use more levels (larger N). This
adaptive approach ensures that the communication overhead
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 9

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52365
is minimized without compromising model accuracy. AQ is
scalable to large IoT networks with diverse device capabilities,
making it suitable for real-world deployments.
F . SA Process
A detailed explanation of our proposed PPFL scheme is
presented in the following. The approach integrates HE with
the double-masking technique introduced by Bonawitz et al.
[20], which helps to protect intermediate data from unau-
thorized access during model updates. The double-masking
mechanism employs two layers of masking—one applied to
each client’s local update and another to the aggregated result
to ensure the correctness of the aggregation while maintaining
the privacy of each client’s contribution. This is particularly
important in FL environments, where ensuring the privacy of
each client’s local model update is crucial for maintaining
trust and security. In addition, the quantization (data quality)
contribution rate is considered, making the scheme more
suitable for FL environments. Sections III-F.1–III-F.4 describe
the system’s construction in detail.
1) System Initialization: A secure communication frame-
work designed to protect the conﬁdentiality of interactions
between the cloud server and connected devices is described
in the following. The framework relies on symmetric session
keys, as detailed in Algorithm 1 [75], and involves several key
stages: device enrollment, authentication, key establishment,
and mutual veriﬁcation. Each of these stages is explained in
detail as follows.
1) Data Evaluation Stage: Each device transmits its
encrypted data securely to the cloud server. Upon recep-
tion, the cloud server aggregates the encrypted data
and securely distributes the aggregated result to all
participating devices in an encrypted manner, ensuring
protection against potential adversaries.
2) Device Enrollment Stage: Every authorized device must
undergo a registration process with the RA. During reg-
istration, the RA assigns a unique identiﬁer, denoted as
IDU, and generates a conﬁdential authentication param-
eter. The hashed identity of the device, represented as
HIDU, is computed using (17), while the authentication
parameter, labeled as AUTH U, is derived using (18)
HIDU = hash (IDU) (17)
AUTHU = hash (IDU||MACU). (18)
The cloud server securely stores each device’s authenti-
cation parameters. If a device attempts to register with
an already-assigned identiﬁer, the registration request is
denied.
3) Authentication Stage: During authentication, the device
transmits HID U to the server for veriﬁcation. Upon
receiving the request, the server searches for the corre-
sponding HIDU in its database. If a match is found, the
server retrieves the associated AUTH U. The server then
generates two large random values, S 1 and S 2. Using
(19) and (20), the server computes A∗ and B∗, which
are sent to the device
A∗ = (S 1⊕ AUTHU) (19)
B∗ = (S 2⊕ AUTHU). (20)
Upon receiving A∗ and B∗, the device extracts S 1 and
S 2 using the following computations:
S 1 = (A∗⊕ AUTHU) (21)
S 2 = (B∗⊕ AUTHU). (22)
Algorithm 1 Secure Symmetric Key Exchange
Require: S : A variable initialized with a 128-bit value.
The server stores the device identity ( HID U) and a secret
value (AUT HU).
1 The device transmits its identity ( HID U) to the server.
2 if HID U matches the stored identity then
3 The server generates two secret values, S 1 and S 2,
and securely sends them to the device as A∗ and B∗,
respectively.
4 The device generates a random number KEY U.
5 if The server’s random number KEY S = 0 then
6 Go to Step 4.
7 end if
8 Compute INT U = (KEY U× S 1) + S 1.
9 Compute FKEY U = (INT U× S 2) + S 1 + S 2.
10 Send FKEY U to the server.
11 Calculate INT S = FKEY U− (S 1 + S 2).
12 Calculate KEY U = (INT S/(S 1× S 2))− 1.
13 end if
14 The server generates a random number KEY S .
15 if KEY S = 0 then
16 Go to Step 13.
17 end if
18 Compute INT S = (KEY S× S 1) + S 1.
19 Compute FKEY S = (INT S× S 2) + S 1 + S 2.
20 Send FKEY S to the device.
21 Both the server and the device repeat steps 11 to 12.
22 Compute the shared key as KDS = (KEY U⊕ KEY S )
mod M.
23 if KDS = 0 then
24 Go to Step 4.
25 end if
26 if Identities do not match then
27 Terminate the connection.
28 end if
4) Key Establishment Stage: A 128-bit random value,
denoted as KEY U, is generated. It is then used to
compute an intermediate result as follows:
INTU = (KEYU∗ S 1) + S 1. (23)
The device transmits the ﬁnal result, FKEY U, to the
server
FKEYU = (INTU∗ S 2) + S 1 + S 2. (24)
Since FKEY U does not directly expose KEY U, an
attacker intercepting this value cannot reconstruct the
key. Upon receiving FKEY U, the server calculates the
intermediate diﬀerence
INTS = FKEYU− (S 1 + S 2). (25)
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 10

52366 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
Algorithm 2 Adaptive Quantization for FL
Require: Number of devices N, model update vectors xi
for each user i where xi(k)∈ [r1, r2], quantization levels
K(i)
g for each user i, range [ r1, r2].
Ensure: Aggregated model update ¯x.
1 Step 1: User-Side Quantization
2 for each user i = 1, 2,..., N do
3 Compute quantization interval:
∆(i)
Kg = r2− r1
K(i)
g − 1
4 Deﬁne quantization thresholds:
T (i)(l) = r1 + l· ∆(i)
Kg for l = 0, 1,..., K(i)
g − 1
5 Quantize each element xi(k) of the model update vector
xi:
6 for each element xi(k) do
7 Find the interval l such that xi(k)∈ [T (i)(l), T (i)(l +
1)).
8 Compute the probability p for rounding up:
p = xi(k)− T (i)(l)
T (i)(l + 1)− T (i)(l)
9 Quantize xi(k) stochastically to integer levels:
Q(i)
Kg(xi(k)) =
(
l + 1 with probability p,
l otherwise.
10 end for
11 Transmit quantized model update vector Q(i)
Kg(xi) to the
server.
12 end for
13 Step 2: Server-Side Aggregation
14 Receive quantized updates Q(i)
Kg(xi) from all devices i =
1, 2,..., N.
15 Normalize each quantized update:
˜xi(k) = Q(i)
Kg(xi(k))· ∆(i)
Kg
16 Compute the aggregated model update ¯ x:
¯x(k) = 1
N
NX
i=1
˜xi(k)
17 Update the global model using ¯ x.
18 return Aggregated model update ¯x.
Using S 1 and S 2, the server retrieves the hidden key
value
KEYU = (INTS/ (S 1∗ S 2))− 1. (26)
Once both entities derive shared secret values, denoted
as KEY U and KEY S, they compute a ﬁnal session key
using a bitwise XOR operation followed by a modu-
lus operation with a predeﬁned 128-bit value M, as
expressed in the following equation:
KS = (KEYU⊕ KEYS ) mod M. (27)
5) Identity Veriﬁcation Stage: After establishing a symmet-
ric session key, both the cloud server and the registered
agent validate their identities to prevent MITM attacks.
Each party computes an HMAC using the symmet-
ric session key, incorporating their IP addresses and
randomly generated numbers, as shown in (28) and
(29). SHA-256 is used to generate a 64-bit ﬁxed-length
authentication code. The computed HMAC values are
exchanged and validated; authentication succeeds if both
match. Otherwise, the connection is terminated
HMACU = SHA− 256 (IPU||NU, KS ) (28)
HMACS = SHA− 256 (IPS||NS, KS ). (29)
6) Encryption Stage: Once mutual authentication is com-
plete, encrypted data exchange is conducted between
the cloud server and the agent using HE to ensure data
conﬁdentiality.
2) Masking of the Local Model: Upon receiving the
required messages, each device trains its local model wt
i using
the stochastic gradient descent (SGD) algorithm. Prior to
transmitting the local model to the server, the device assesses
the data quality Qt
i through quantization. To safeguard against
potential eavesdropping by malicious external adversaries,
including the server and other participating clients, a crypto-
graphic protocol is employed for secure information exchange
among all clients, ensuring privacy preservation.
At the beginning of each training epoch t, client i generates
a private key sskt
i and applies the secret-sharing algorithm
to distribute the key securely among the participating clients.
This process ensures that no single entity possesses complete
knowledge of the private key, thereby enhancing the security
and privacy of the FL framework
sskt
i
S S S:share(sskt
i;e;P1)−−−−−−−−−−−−−−−→
˚
sskt
i, j
	
j∈P1\{i}. (30)
To securely distribute sskt
i, client i ﬁrst divides it into n
distinct shares. Next, client i uses the Di ﬃe–Hellman key
agreement function, denoted as fD−H, to establish a symmetric
key with every other participating client j in the group P1,
excluding itself (i.e., j∈ P1\{ i}). This ensures that each share
is securely transmitted to the respective clients.
The symmetric key is computed as ci, j = fD−H(cski, cpk j),
ensuring a secure communication channel between the clients.
Subsequently, client i encrypts each secret share sskt
i, j using
the corresponding symmetric key ci, j, producing the ciphertext
cttt
i, j = Encci, j(sskt
i, j). The encrypted share, along with the
sender and recipient identiﬁers ( i, j, cttt
i, j), is then transmitted
to client j for secure key distribution.
After receiving the ciphertexts {(i, j, cttt
i, j)}i∈P2\{ j} from at
least e clients, where P2⊆ P1, client j computes the symmetric
key c j,i = fD−H(csk j, cpki) with each respective client i using
the Di ﬃe–Hellman key agreement function. Each received
ciphertext cttt
i, j is then decrypted using the corresponding
symmetric key c j,i, retrieving the secret share as sskt
i, j =
Decc j,i(cttt
i, j). The decrypted secret shares are securely stored
by client j for future use.
After training its local model wt
i and determining the
data quality Qt
i, client i computes the symmetric key st
i, j =
fD−H(sskt
i, spk t
j) with other clients j∈ P2\{ i}. This key serves
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 11

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52367
as the seed for a pseudorandom generator (PRG) to derive the
masked local model
yt
i = wt
iQt
i +
X
j∈P2\{i},
i< j
PRG
 
st
i, j

−
X
j∈P2\{i},
i> j
PRG
 
st
i, j

+φQt
i mod R (31)
where φ is a predeﬁned public scale factor. Since PRG( st
i, j)
and φQt
i are scalar values, they are expanded to match the
dimension of wt
iQt
i. In addition, Qt
i undergoes quantization,
involving rounding to n decimal places and scaling by 10 n
to yield an integer representation. On the server, the inverse
operation restores it to a ﬂoating-point value by scaling down
by 1/(10n). The precision parameter n remains tunable in
experiments.
After masking its local model, client i encrypts Qt
i using an
enhanced version of the ElGamal HE scheme and the system’s
public key gs. To do this, client i randomly chooses a value ri
from Z∗
q and calculates the ciphertext as shown in the following
equation:
Encspksys
 
Qt
i

= (ci1, ci2) =
 
gri, 2Qt
igsri

. (32)
Client i then transmits ( i, yt
i, ci1, ci2) to the server.
3) Local Model Aggregation: Once the server collects
masked models and ciphertexts ( i, yt
i, ci1, ci2) from a minimum
of e clients (represented as P3⊆ P2), it begins the aggregation
process.
First, it veriﬁes whether P3 = P2. If true, it aggregates
{yt
i}i∈P3 directly. Otherwise, it identiﬁes dropped clients in
P2\ P3 and broadcasts their identities to all clients, requesting
the submission of the corresponding secret shares. Upon
receiving this request, client j voluntarily submits{sskt
i, j}i∈P2\P3
to the server.
If the server collects shares from at least e clients (denoted
as P4), it reconstructs the missing private keys
˚
sskt
i, j
	
j∈P4\{i}
S S S:recons

e;
n
sskt
i, j
o
j∈P4\{i}

−−−−−−−−−−−−−−−−−−−−−→sskt
i. (33)
The server then performs aggregation using the following
equation:
θ =
X
i∈P3
yt
i +
X
i∈P2\P3, j∈P3,
i< j
PRG
 
st
i, j

−
X
i∈P2\P3, j∈P3,
i> j
PRG
 
st
i, j

. (34)
Finally, the global model is computed using the following
equation:
wt
global =
θ−φP
i∈P3 Qt
iP
i∈P3 Qt
i
. (35)
4) Veriﬁcation Phase: To ensure the correctness of the
aggregated gradients, veriﬁcation proceeds in two steps.
1) Veriﬁcation: Each client i ∈ P3 veriﬁes aggregated
gradients vagg using the following equation:
E′ =
dY
l=1
gvagg[l]hB. (36)
If (36) holds, training continues; otherwise, the result is
rejected.
2) Batch Veriﬁcation: For e ﬃciency, client i randomly
selects m epochs and computes using the following
equation:
E′′ =
mY
k=1
E′. (37)
If veriﬁcation is successful, training proceeds; otherwise,
inconsistencies are detected, and faulty updates are dis-
carded.
IV. S ECURITY ANALYSIS
In our proposed model, both the server and clients operate
under the semihonest (honest-but-curious) adversarial model,
meaning they follow the protocol faithfully but may attempt to
infer sensitive information from the data they observe. Under
this model, we analyze the security of two key components:
the masking mechanism and the HE scheme. The analysis
focuses on ensuring privacy and robustness against collusion
and dropout attacks.
A. Security of the Masking Mechanism
The masking mechanism is designed to protect the real
inputs of clients during the aggregation process. Each client’s
real input, denoted as aut i = wtiQi
t + φQi
t, is obscured by
introducing random numbers. These random numbers ensure
that the masked values appear indistinguishable from random-
ness, making it computationally infeasible for adversaries to
extract individual client inputs. The security of the masking
mechanism relies on the following properties.
1) Aggregation Privacy:
1) The combined masked values from all devices are equal
to the sum of the real inputs from the devices. This guar-
antees that attackers can only see the ﬁnal aggregated
result, without being able to access or infer individual
contributions.
2) The masking mechanism guarantees that no single
client’s input can be reconstructed by the server or other
clients, preserving privacy.
2) Computational Indistinguishability:
1) The masked values are computationally indistinguish-
able from random values. This is formalized in the
following lemma.
Given a ring ZR and a set of participants P, for all i, j∈ P,
where aui∈ ZR, the following distributions are computation-
ally indistinguishable:
n˚
PRGi; j← ZR
	
i< j ∀i> j, PRGi; j←− PRG j;i :
8
<
:aui +
X
j∈P\{i}
PRGi; j
9
=
;
i∈P
9
=
;
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 12

52368 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
≡
(
{ξi← ZR}i∈P, s.t.
X
i∈P
ξi =
X
i∈P
aui :{ξi}i∈P
)
.
Here,≡ denotes computational indistinguishability between
the two distributions.
3) Collusion Resistance:
1) The analysis considers two collusion scenarios: 1) client-
only collusion and 2) collusion involving both clients
and the server.
2) Clients are classiﬁed into subsets P5⊆ P4⊆ P3⊆ P2⊆
P1, where P1 represents all clients, P2 includes clients
engaged in model masking, P3 consists of online clients,
P4 includes clients providing secret shares for dropped
clients, and P5 includes clients involved in data quality
decryption.
3) The server is denoted as S , and the set of colluding
entities is represented as A.
B. Security of the HE
The HE scheme ensures the privacy of data quality metrics
and local models. Each client encrypts its data quality Qi
t using
the system’s public key gs, producing ciphertext ( gri, 2Qi
tgsri).
To decrypt Qi
t and infer the local model wti, an adversary
would need to solve the discrete logarithm problem or the
Decisional Di ﬃe–Hellman problem, both of which are com-
putationally infeasible.
1) Collusion Resistance:
1) Even if the server colludes with up to t− 1 clients, they
cannot reconstruct the private key s due to the Shamir
secret-sharing scheme, which requires at least e shares
to recover s.
2) Without access to s, colluding parties can only compute
the sum of data qualities for honest clients, P
i∈P3\A Qi
t,
but cannot decrypt individual Qi
t values.
2) Semantic Security:
1) The HE scheme remains semantically secure as long as
fewer than e clients collude. This ensures that the local
model wti of any honest client remains protected.
C. Veriﬁability and Robustness
The proposed scheme also ensures veriﬁability and robust-
ness against malicious behavior:
Theorem 1: The proposed ROCHE ensures the veriﬁability
of random number shares and aggregated results.
Proof: Each user generates proofs for shares and commit-
ments, which are validated by other devices and the server. If
inconsistencies are detected, the aggregation process is halted,
ensuring the correctness of the results. □
Theorem 2: The proposed ROCHE is resistant to collusion
attacks when the server colludes with at most t− 1 devices.
Proof: Colluding devices cannot access the secret keys of
honest devices, preventing the forgery of commitments. This
ensures that collusion attacks fail. □
Theorem 3: The proposed ROCHE remains robust against
user dropout, provided that at least t devices remain online.
Proof: As long as t devices remain online, the server can
compute the aggregated result using veriﬁable multisecret
sharing, preserving the privacy of dropped devices. □
The security analysis demonstrates that the proposed
scheme provides strong privacy guarantees under the semi-
honest model. The masking mechanism and HE ensure that
individual client inputs remain conﬁdential, even in the pres-
ence of collusion. In addition, the scheme supports veriﬁability
and robustness, making it suitable for secure and e ﬃcient FL.
V. P ERFORMANCE ANALYSIS
In this section, we consider a system comprising a server
and n clients, where the local model has a dimensionality of m
and the threshold for the Shamir secret-sharing algorithm is e.
A theoretical evaluation of the computational and communica-
tion costs incurred during a single epoch of FL is conducted.
Since the system initialization occurs only once and does not
impact the subsequent training process, its cost is excluded
from the analysis.
A. Client’s Cost Analysis
Computation and communication costs of the client are
described in the following.
1) Client’s Computational Cost: The computational com-
plexity for each device in a training epoch is primarily
determined by the following operations.
1) Key Agreement Operations:
a) Each client generates symmetric keys with ( n−
1) other devices by executing the key agreement
function (n− 1) times.
b) Encrypting and decrypting secret shares ssk−t
i; j
requires executing key agreement function another
(n− 1) times.
c) Total key agreement executions: 2( n− 1), leading
to a complexity of O(n).
2) Encryption and Decryption Tasks:
a) Each client encrypts ( n − 1) secret shares
Encci; j(ssk−t
i; j) and decrypts ( n− 1) received shares
Decci; j(ctt
j;i).
b) Total encryption /decryption operations: 2( n− 1),
contributing O(n) complexity.
3) Secret Sharing:
a) Creating secret shares for the private key requires
running the secret-sharing algorithm ( n− 1) times,
with a complexity of O(n).
4) PRG Expansion:
a) The PRG generates a single number, but the local
model is an m-dimensional vector. Each masking
step involves ( n− 1) PRG-generated numbers,
requiring m(n− 1) expansions.
b) This results in a complexity of O(mn).
5) Adaptive Quantization:
a) Each device quantizes its local model updates
based on its resource constraints, using a device-
speciﬁc bit-width bi.
b) The complexity of quantization is O(m) per device.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 13

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52369
6) HE (If Selected):
a) If a client is chosen to assist the server in decryp-
tion, it performs a HE task on the quantized data,
with a complexity of O(1).
7) Total Computational Complexity:
a) Summing all tasks: O(n + n + n + nm + m + 1),
which simpliﬁes to O(nm).
2) Client’s Communication Cost: The communication cost
for each client in a training round is determined by the
following key activities.
1) Secret Share Exchange:
a) Each client transmits ( n− 1) encrypted secret
shares to the other devices and, in turn, receives
(n− 1) encrypted secret shares from them.
2) Uploading Quantized and Masked Model:
a) The client uploads its quantized and masked model
along with the encrypted data quality, represented
as (i, yt
i, ci1, ci2), to the server.
b) The size of the quantized model update is mbi,
where bi is the device-speciﬁc bit-width.
3) Handling Dropouts:
a) If d devices dropout and the client agrees to help,
it sends the secret shares of the dropped devices
to the server.
b) In the worst case, if ( n− e) devices dropout, the
client must transmit ( n− e) shares.
4) Homomorphic Decryption Assistance:
a) If the client is chosen to assist in homomorphic
decryption, it receives cϵi
1 from the server and
responds with λi.
5) Cost Breakdown:
a) ak : Length of the public key.
b) as : Length of the private key.
c) bi : Device-speciﬁc bit-width for quantization.
d) ac : Length of the encrypted quantized data.
e) Sizes of cϵi
1 and λi are equal to the public key
length.
6) Total Communication Cost:
[2(n− 1) + d]as + 2ak + ac + mbi.
7) Minimum Communication Cost (No Dropouts or
Decryption Assistance):
a) For device i, the minimum communication cost is:
2(n− 1)as + ac + mbi.
B. Server’s Cost Analysis
Computation and communication costs of the server are
described in the following.
1) Server’s Computational Cost: The computational cost
for the server in each training epoch consists of the following
operations.
1) Key Reconstruction for Dropped Clients:
a) If d clients dropout, the server must reconstruct
their private keys.
b) This involves performing d secret reconstruction
operations, leading to a complexity of O(d).
2) Symmetric Key Computation for Dropped Clients:
a) For each dropped client, the server calculates ( n−
d) symmetric keys by applying the key agreement
function.
b) Total executions: ( n−d)d, resulting in a complexity
of O(nd).
3) PRG Expansion:
a) Each symmetric key serves as a seed for the
PRG. The server computes ( n− d)d instances of
PRG(st
i; j).
b) Because each (PRG) output needs to be expanded
to m dimensions, the total computational com-
plexity becomes O((n− d)dm), which simpliﬁes
to approximately O(nmd).
4) Homomorphic Decryption of Data Quality:
a) Homomorphic decryption is performed by the
server on the quantized data of ( n− d) active
clients.
b) This process includes:
a) 2( n− d) ciphertext multiplications;
b) e calculations of δi and grϵi
;
c) e multiplications of λi.
3) Since d and e are usually signiﬁcantly smaller than
n, the total computational complexity is simpliﬁed
to O(n).
5) Handling Adaptive Quantization:
a) The server receives quantized model updates from
clients, where each update is quantized with a
device-speciﬁc bit-width bi.
b) The server must aggregate these updates, which
involves decoding and combining the quantized
values.
c) The complexity of aggregation is O(nm), as the
server processes m-dimensional updates from n
clients.
6) Total Computational Complexity:
a) Summing all tasks: O(d + nd + nmd + n + nm)≈
O(nmd).
b) In the worst case scenario, where the number of
dropped clients reaches the system’s limit of ( n−
e), the server’s computational cost is at most
O(nm(n− e))≈ O(mn2).
c) If no clients dropout, Steps 1)–3) are unnecessary,
and the computational complexity is minimized to
O(nm).
2) Server’s Communication Cost: The communication cost
incurred by the server in a training epoch comprises the
following activities.
1) Receiving Masked Models and Data Quality:
a) The server receives masked models and encrypted
quantized data from the ( n− d) active clients.
b) The size of each update depends on the device-
speciﬁc quantization bit-width bi.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 14

52370 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
2) Broadcasting Dropped Clients’ Identities:
a) The server sends a notiﬁcation to all active clients
containing the identities of the clients that have
been dropped.
b) This operation is lightweight and has negligible
communication cost.
3) Collecting Secret Shares for Key Reconstruction:
a) The server gathers secret shares from active clients
to recover the private keys of the dropped clients
b) Each client submits d shares, resulting in a total
of ed secret shares received by the server.
4) Homomorphic Decryption Assistance:
a) The server utilizes e active clients to assist in the
homomorphic decryption.
b) During this process, the server transmits cϵi
1 e times
and receives λi e times.
5) Cost Breakdown:
a) ak: Length of the public key.
b) as: Length of the private key.
c) bi: Device-speciﬁc bit-width for quantization.
d) ac: Length of the encrypted quantized data.
e) Sizes of cϵi
1 and λi are equal to the public key
length.
6) Total Communication Cost:
a) The total communication cost for the server is
edas + 2eak + (n− d)ac + (n− d)m⌈log2 R⌉.
b) Here, R = 2bi represents the range of quantized
values for each device.
7) Minimum Communication Cost (No Dropouts):
a) If no clients dropout, the server does not need
to collect secret shares or assist in homomorphic
decryption.
b) The communication cost reduces to
2eak + nac + nm⌈log2 R⌉.
VI. E XPERIMENTAL SETUP
All experiments were conducted using Python 3 on a
Windows 10 Pro 64-bit system (Intel Core i7, 2.3 GHz, 32-GB
RAM). The training process utilized the PyTorch framework
within the VS Code environment to train the speciﬁed CNN
model. For the inference phase, the Python implementation of
SEAL, known as Pyfhel [76], was employed to enable privacy-
preserving model classiﬁcation.
A. Datasets
We assess and validate the performance of the proposed
IDS model using three datasets: TON IoT, Edge-IIoT, and
X-IIoTID. The details are as follows.
1) TON IoT Dataset: TON IoT [77] is speciﬁcally
designed to evaluate IIoT defense solutions. It consists of var-
ious IoT-related attacks and legitimate instances. The dataset
contains 46 labeled features, distinguishing normal and attack
instances as a multiclass classiﬁcation problem. The common
cyberattack types in TON IoT include
TABLE II
TRAINING AND TEST SAMPLES OF TON IOT D ATASET
TABLE III
TRAINING AND TEST SAMPLES OF EDGE -II OT D ATASET
1) Scanning: Attackers probe a target network to uncover
potential entry points and vulnerabilities.
2) DoS: Flooding attack that overwhelms system resources
such as bandwidth, memory, or processing power.
3) DDoS: Multiple connections ﬂood a target IIoT device,
exhausting its resources.
4) Ransomware: Encrypts system ﬁles and demands pay-
ment for decryption.
5) Backdoor: Bypasses security mechanisms to gain unau-
thorized access.
6) Injection Attack: Manipulates data/control commands of
an IIoT system.
7) XSS: Injects malicious scripts into web pages.
8) Password Violations: Involves methods like password
cracking, sniﬃng, and brute-force attacks.
9) MITM Attack: Eavesdrops and intercepts communica-
tions between two parties.
Table II presents the number of records per attack category
within the TON IoT dataset.
2) Edge-IIoT Dataset: Edge-IIoT [78] collects data from a
seven-layer testbed in a federated architecture. It includes ten
IoT devices and ModBus-based IIoT communication ﬂows.
The dataset covers 14 types of attacks, categorized into ﬁve
major threat groups: DDoS, scanning, malware, injection, and
MITM. Table III summarizes the dataset distribution.
3) X-IIoTID Dataset: X-IIoTID [79] follows the Indus-
trial Internet Reference Architecture model, consisting of the
edge, platform, and enterprise levels. The dataset is classi-
ﬁed into nine primary attack categories, further divided into
18 subattack types such as reconnaissance, weaponization,
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 15

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52371
TABLE IV
TRAINING AND TEST SAMPLES OF X-II OTID D ATASET
exploitation, lateral movement, command and control (C&C),
crypto-ransomware, ransom dos, exﬁltration, and tampering.
The dataset consists of 421 417 normal records and 399 417
attack records, with 59 extracted features from network tra ﬃc,
device resources, and alert logs. Table IV provides an overview
of the dataset.
For more details about these datasets, refer to [77], [78],
and [79].
B. Evaluation Metrics
The evaluation of the proposed IDS model’s performance
is conducted by analyzing several key metrics: true positive
(TP), true negative (TN), FP, and false negative (FN). The term
TP indicates correctly predicted malicious data, TN indicates
correctly predicted normal data, FP indicates normal data that
is predicted as malicious data, and FN indicates malicious data
misjudged as normal data. Evaluation metrics considered for
the assessment and validation of the proposed scheme are as
follows:
Accuracy = TP + TN
TP + TN + FP + FN (38)
Recall = TP
TP + FN (39)
Precision = TP
TP + FP (40)
F1-Score = TP
TP + 1
2 (FP + FN). (41)
VII. R ESULTS AND COMPARATIVE ANALYSIS
The communication model employed in the experimental
setup incorporates speciﬁc assumptions and conﬁgurations.
The noise power N0 is assumed to be −174 dBm, while
the maximum transmitting power of each device is set to
30 dBm. The bandwidth Bmax is designated as 100 MHz,
and the channel gain gi,u is modeled using Rayleigh fading,
with an average path loss of 10 −3. In addition, the model
parameters are quantized into 16 bits before transmission to
optimize the communication process. Regarding the comput-
ing model, the CPU core frequency is set to 1100 MHz, and
1i = 20 cycles /bit, ensuring adequate processing capabilities
for the IDS and related computations.
Fig. 5. (a) Accuracy. (b) Training loss of the proposed IDS model on the
TON IoT dataset.
Fig. 6. ROC curve of proposed IDS model on TON IoT dataset.
The performance of the proposed IDS models is compared
with the following FL and non-FL-based IDS models.
1) Centralized Model: A nonfederated approach where the
entire dataset is collected and trained on a central server
without any data distribution among devices.
2) FedAvg [80]: A standard FL approach where all devices
participate in the training process without considering
data distribution criteria.
Fig. 5(a) and (b) shows the achieved accuracy and loss with
the TON IoT dataset using the proposed IDS model. It is
observed that the accuracy and loss of 99.95% and 0.0023%
have been achieved, respectively. Furthermore, Fig. 6 reﬂects
the area under the ROC curve that demonstrates the e ﬀective
detection capabilities of the proposed model.
A. Performance Comparison Using Di ﬀerent Datasets and
FL Baseline Schemes
To evaluate the performance of the proposed framework,
experiments are conducted on public datasets that speciﬁcally
consider the wide domain of intrusion attack categories in
IoT/IIoT scenarios and compared with existing FL baseline
IDS models as illustrated in Tables V–VII. As described in
Table V, the proposed model outperforms as compared with
baseline models using the TON IoT dataset. The accuracy
achieved with the proposed model is 99.95%, precision is
98.63%, recall is 99.98%, and F1-score is 99.99%. In the
literature, the researchers have presented various IDS models
with their prime focus on attack vectors and ignored their
attention to enhance the performance of the FL system while
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 16

52372 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
TABLE V
PERFORMANCE COMPARISON USING TON IOT D ATASET
TABLE VI
PERFORMANCE COMPARISON USING EDGE II OT D ATASET
TABLE VII
PERFORMANCE COMPARISON USING X-II OTID D ATASET
minimizing the energy consumption. The o ﬀered solution in
this study successfully addresses these issues, not only detects
the network intrusion but also enhances the performance of
FL with the integration of DRL to select high-quality client
devices for the global aggregation model.
Table VI illustrates the performance comparison of the
proposed model with existing FL baseline models using the
Edge IoT dataset. The accuracy achieved by our proposed
model is 97.90% in multiclass classiﬁcation. Also, a high
value of precision, recall, and F1-score is scored as compared
with other baseline models. The performance of proposed and
existing IDS models is also examined using the X-IIoTID
dataset. It consists of nine attack subcategories which is
accurately classiﬁed as multiclass classiﬁcation with an
accuracy of 99.99%, whereas other baseline schemes achieve
an accuracy of 90.24% and 81.35% under a similar scenario
as shown in Table VII.
The proposed ROCHE model outperforms both centralized
and simple FL models in accuracy, convergence speed, and
eﬃciency as shown in Fig. 7. While the centralized model
achieves high accuracy, it faces privacy risks, high commu-
nication costs, and scalability issues. The simple FL model
Fig. 7. Accuracy comparison of the centralized model, simple FL model,
and proposed ROCHE model over 50 training rounds. ROCHE achieves
faster convergence and higher accuracy compared with the simple FL model,
approaching the performance of the centralized model.
enhances privacy but suﬀers from slow convergence and lower
accuracy due to non-IID data and ine ﬃcient aggregation.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 17

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52373
Fig. 8. Average encryption and decryption time with various key lengths for
HE.
Fig. 9. Computational cost analysis of various FL approaches, including
secret-sharing FL [66], ShieldFL [71], IoV FL [67], MITFed [68], and the
proposed ROCHE, with respect to increasing vector dimensions.
ROCHE overcomes these challenges through Chebyshev
polynomial optimization, incorporating adaptive interval selec-
tion, iterative coe ﬃcient updates, and an error feedback
mechanism. These enhancements enable faster convergence,
improved accuracy, and better scalability in ICPS IDS. The
results demonstrate that DCO-FL is a practical and e ﬃcient
solution for real-time IoT security applications.
B. Average Encryption and Decryption Time
Fig. 8 illustrates the encryption and decryption time (in
seconds) for di ﬀerent key lengths (512-, 1024-, 2048-, and
3072-bit) is calculated in this experiment. The encryption time
is represented by the blue bars, while the decryption time is
shown in green. These results emphasize the tradeo ﬀ between
security and computational e ﬃciency in cryptographic oper-
ations. While larger key sizes provide stronger security, they
impose a signiﬁcant computational cost, which is a crucial
consideration for real-time industrial applications, including
secure communication in IIoT and FL-based IDS systems. We
use a key length of 512 bits to encrypt and decrypt model
parameters in this work.
C. Computational Cost
Figs. 9 and 10 present the computational cost variations
with increasing vector dimensions and the number of devices,
Fig. 10. Computational cost comparison of various FL approaches, including
secret-sharing FL [66], ShieldFL [71], IoV FL [67], MITFed [68], and the
proposed ROCHE, with respect to the number of devices.
respectively. As observed in Fig. 9, secret-sharing FL [66]
exhibits the highest computational overhead, increasing lin-
early as the vector dimension scales. This behavior is attributed
to the high complexity of secret-sharing schemes, which
require extensive cryptographic operations for SA. ShieldFL
[71] and IoV FL [67] demonstrate reduced but still consid-
erable computational costs, primarily due to their reliance
on SMPC and HE, both of which introduce signiﬁcant over-
head. While MiTFed [68] achieves better e ﬃciency, ROCHE
signiﬁcantly outperforms all baselines, exhibiting the lowest
computational cost across all vector dimensions. This e ﬃ-
ciency gain is due to ROCHE’s DCO framework, which
iteratively reﬁnes interval selection and updates Chebyshev
coeﬃcients, thereby reducing unnecessary computations while
maintaining accuracy.
A similar trend is observed in Fig. 10, where computa-
tional cost scales linearly with the number of devices. The
cryptographic-heavy secret-sharing FL [66] method incurs
substantial computational delays, whereas ROCHE demon-
strates superior scalability, maintaining the lowest computa-
tional burden as the number of devices increases. This behavior
further validates ROCHE’s adaptive optimization strategy,
which dynamically distributes computational workloads and
minimizes redundant operations, making it well-suited for
large-scale FL environments.
The superior computational e ﬃciency of ROCHE is pri-
marily attributed to its DCO framework, which e ﬃciently
approximates AFs and iteratively updates Chebyshev coef-
ﬁcients, signiﬁcantly reducing the number of expensive
operations while maintaining high accuracy. Furthermore, the
integration of error feedback mechanisms minimizes redundant
computations, ensuring lower complexity while preserving pri-
vacy. These optimizations collectively contribute to ROCHE’s
substantial computational cost reduction, making it the most
eﬃcient scheme among the compared frameworks.
D. Communication Cost
Figs. 11 and 12 illustrate the communication cost in
megabytes (MB) as a function of vector dimension and the
number of devices, respectively. As observed in Fig. 11, secret-
sharing FL [66] imposes the highest communication cost due
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 18

52374 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
Fig. 11. Communication cost analysis of di ﬀerent FL approaches, including
secret-sharing FL [66], ShieldFL [71], IoV FL [67], MITFed [68], and the
proposed ROCHE, across varying vector dimensions.
Fig. 12. Communication cost comparison of various FL approaches, including
secret-sharing FL [66], ShieldFL [71], IoV FL [67], MITFed [68], and the
proposed ROCHE, with respect to the number of devices.
to excessive encrypted data exchanges required for SA. While
ShieldFL [71] and IoV FL [67] reduce the communication
overhead by leveraging hybrid encryption and DP, they still
suﬀer from excessive bandwidth consumption. MiTFed [68]
enhances eﬃciency by incorporating compression techniques,
but ROCHE achieves the lowest communication overhead
across all dimensions. This reduction is primarily attributed
to ROCHE’s lightweight privacy-preserving framework, which
optimizes the encoding of model updates while ensuring
security, signiﬁcantly reducing transmission requirements.
Fig. 12 further conﬁrms ROCHE’s scalability in handling
a growing number of devices. While secret-sharing FL [66],
ShieldFL [71], and IoV FL [67] exhibit steep increases in
communication cost as the number of devices grows, ROCHE
maintains a substantially lower rate of increase. This advantage
stems from its error-feedback integration mechanism, which
eﬃciently compresses update exchanges without compromis-
ing model integrity. These results validate ROCHE’s capability
to support large-scale FL with reduced communication over-
head, a critical factor for ICPS where network resources are
constrained.
The enhanced communication e ﬃciency of ROCHE is
primarily due to its lightweight federated aggregation mecha-
nism, which reduces the model update size through adaptive
interval selection. Unlike conventional schemes that transmit
large amounts of encrypted data, ROCHE optimizes message
passing with structured sparsiﬁcation, signiﬁcantly reducing
bandwidth requirements while maintaining robust security.
This makes ROCHE the most e ﬃcient communication frame-
work among the compared methods, ensuring scalability and
adaptability for large-scale FL environments.
VIII. C ONCLUSION AND FUTURE WORK
In this article, we proposed ROCHE, a privacy-preserving
and communication-e ﬃcient FL framework for IDS in IIoT.
Unlike existing PPFL-based IDS frameworks, which su ﬀer
from high computational overhead, excessive communication
costs, and security vulnerabilities, ROCHE integrates novel
optimizations to enhance e ﬃciency, privacy, and security.
Speciﬁcally, ROCHE employs low-degree Chebyshev poly-
nomials to approximate nonlinear AFs, signiﬁcantly reducing
computational complexity while ensuring model accuracy. In
addition, the adaptive quantization mechanism dynamically
adjusts quantization levels based on available bandwidth,
leading to a substantial reduction in communication overhead.
To further enhance privacy, we introduce an SA scheme that
integrates symmetric HE with single masking, ensuring local
and global model privacy while maintaining robustness to user
dropout through additive homomorphism properties of secret
sharing. Our extensive experimental evaluation on real-world
IIoT attack datasets demonstrates that ROCHE e ﬀectively
detects multiple cyber threats, including DoS, DDoS, MITM,
and injection attacks, with an average detection accuracy
exceeding 92%. Furthermore, ROCHE achieves up to 75%
lower computational cost and 65% lower communication over-
head compared with secret-sharing FL, ShieldFL, IoV FL, and
MiTFed. These results validate ROCHE’s scalability, security,
and e ﬃciency, making it a practical solution for privacy-
preserving, real-time IDS in IIoT environments. In addition,
the deployment of ROCHE in a cloud-based ICPS further
reinforces its feasibility in real-world IIoT applications.
Future enhancements to the ROCHE framework will explore
the integration of adaptive encryption mechanisms to further
optimize the balance between privacy and computational e ﬃ-
ciency. Unlike ﬁxed encryption schemes, adaptive encryption
dynamically adjusts the strength and type of cryptographic
operations based on the contextual sensitivity of data, device
resource constraints, and communication conditions. This
approach will enable stronger protection for highly sensitive
updates while applying lightweight encryption or masking for
less critical data, thus reducing latency and preserving energy
eﬃciency. Adaptive encryption will make the system more
responsive to real-time threats, more scalable across heteroge-
neous IIoT nodes, and more aligned with the principles of fog
and edge computing.
To further enhance the scalability of ROCHE, future
work will explore optimization strategies for the feder-
ated model aggregation process. While ROCHE currently
employs a dropout-tolerant symmetric homomorphic aggre-
gation scheme, additional techniques such as asynchronous
aggregation, cluster-based hierarchical aggregation, and adap-
tive client selection can signiﬁcantly reduce communica-
tion bottlenecks and improve system responsiveness. These
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 19

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52375
enhancements will allow the framework to better support
large-scale, heterogeneous IIoT deployments with intermittent
connectivity and diverse device capabilities, thereby improving
convergence eﬃciency and robustness.
Moreover, in the future, we aim to integrate blockchain-
based veriﬁcation mechanisms to ensure tamper-proof logging
and veriﬁability of client model updates. A lightweight per-
missioned blockchain (e.g., Hyperledger or Tendermint) can be
employed to record cryptographic hashes of encrypted updates
and client contributions. This would enable auditability, trust-
less veriﬁcation, and detection of adversarial or noncompliant
behavior during the FL process, thereby strengthening the
transparency and robustness of the intrusion detection frame-
work in decentralized IIoT settings.
REFERENCES
[1] R. Lohiya and A. Thakkar, “Application domains, evaluation data sets,
and research challenges of IoT: A systematic review,” IEEE Internet
Things J., vol. 8, no. 11, pp. 8774–8798, Jun. 2021.
[2] S. Kumar, P. Tiwari, and M. Zymbler, “Internet of Things is a revolu-
tionary approach for future technology enhancement: A review,” J. Big
Data, vol. 6, no. 1, pp. 1–21, Dec. 2019.
[3] D. Borsatti, G. Davoli, W. Cerroni, and C. Ra ﬀaelli, “Enabling industrial
IoT as a service with multi-access edge computing,” IEEE Commun.
Mag., vol. 59, no. 8, pp. 21–27, Aug. 2021.
[4] E. Sisinni, A. Saifullah, S. Han, U. Jennehag, and M. Gidlund,
“Industrial Internet of Things: Challenges, opportunities, and directions,”
IEEE Trans. Ind. Informat., vol. 14, no. 11, pp. 4724–4734, Nov. 2018.
[5] R. Kumar, B. Kandpal, and V . Ahmad, “Industrial IoT (IIOT): Security
threats and countermeasures,” in Proc. Int. Conf. Innov. Data Commun.
Technol. Appl. (ICIDCA), Mar. 2023, pp. 829–833.
[6] A.-R. Sadeghi, C. Wachsmann, and M. Waidner, “Security and pri-
vacy challenges in industrial Internet of Things,” in Proc. 52nd
ACM/EDAC/IEEE Design Autom. Conf. (DAC) , Jun. 2015, pp. 1–6.
[7] ABI Research. (2023). Connected & Protected: The Vulnerabilities and
Opportunities of IoT Security. Accessed: Apr. 10, 2025. [Online]. Avail-
able: https://go.abiresearch.com/lp-the-vulnerabilities-and-opportunities-
of-iot-security?utm source=media&utm medium=email
[8] Z. Ji, Z. C. Lipton, and C. Elkan, “Di ﬀerential privacy and machine
learning: A survey and review,” 2014, arXiv:1412.7584.
[9] D. C. Nguyen et al., “Federated learning for industrial Internet of
Things in future industries,” IEEE Wireless Commun. , vol. 28, no. 6,
pp. 192–199, Dec. 2021.
[10] S. Agrawal et al., “Federated learning for intrusion detection sys-
tem: Concepts, challenges and future directions,” Comput. Commun. ,
vol. 195, pp. 346–361, Nov. 2022.
[11] L. Zhu, Z. Liu, and S. Han, “Deep leakage from gradients,” in Proc.
Adv. Neural Inf. Process. Syst. , 2019, pp. 14774–14784.
[12] J. Geiping, H. Bauermeister, H. Dr ¨oge, and M. Moeller, “Inverting
gradients-how easy is it to break privacy in federated learning?,” in
Proc. Adv. Neural Inf. Process. Syst. , vol. 33, 2020, pp. 16937–16947.
[13] B. Hitaj, G. Ateniese, and F. Perez-Cruz, “Deep models under the GAN:
Information leakage from collaborative deep learning,” in Proc. ACM
SIGSAC Conf. Comput. Commun. Secur. , Oct. 2017, pp. 603–618.
[14] G. K. Jagarlamudi, A. Yazdinejad, R. M. Parizi, and S. Pouriyeh,
“Exploring privacy measurement in federated learning,”J. Supercomput.,
vol. 80, no. 8, pp. 10511–10551, May 2024.
[15] Z. Yang, M. Chen, K.-K. Wong, H. V . Poor, and S. Cui, “Federated
learning for 6G: Applications, challenges, and opportunities,” Engineer-
ing, vol. 8, pp. 33–41, Jan. 2022.
[16] P. Qi, D. Chiaro, A. Guzzo, M. Ianni, G. Fortino, and F. Piccialli, “Model
aggregation techniques in federated learning: A comprehensive survey,”
Future Gener. Comput. Syst. , vol. 150, pp. 272–293, Jan. 2024.
[17] M. Le, T. Huynh-The, T. Do-Duy, T.-H. Vu, W.-J. Hwang, and
Q.-V . Pham, “Applications of distributed machine learning for the
Internet-of-Things: A comprehensive survey,” IEEE Commun. Surveys
Tuts., vol. 27, no. 2, pp. 1053–1100, 4th Quart., 2025.
[18] X. Lyu, J. Liu, C. Ren, and G. Nan, “Security-communication-
computation tradeo ﬀ of split decisions for edge intelligence,” IEEE
Wireless Commun., vol. 31, no. 3, pp. 257–263, Jun. 2024.
[19] X. Zhang, F. Wan, C. Liu, R. Ji, and Q. Ye, “FreeAnchor: Learning
to match anchors for visual object detection,” in Proc. Adv. Neural
Inf. Process. Syst. Red Hook, NY , USA: Curran Associates, Oct. 2019,
pp. 1–9.
[20] K. Bonawitz et al., “Practical secure aggregation for privacy-preserving
machine learning,” in Proc. ACM SIGSAC Conf. Comput. Commun.
Secur., Oct. 2017, pp. 1175–1191.
[21] F. Tram `er, F. Zhang, A. Juels, M. K. Reiter, and T. Ristenpart, “Stealing
machine learning models via prediction APIs,” in Proc. 25th USENIX
Secur. Symp., 2016, pp. 601–618.
[22] T. D. Nguyen et al., “FLAME: Taming backdoors in federated learning,”
in Proc. 31st USENIX Secur. Symp. , 2022, pp. 1415–1432.
[23] R. C. Geyer, T. Klein, and M. Nabi, “Di ﬀerentially private federated
learning: A client level perspective,” 2017, arXiv:1712.07557.
[24] W. Wei, L. Liu, Y . Wu, G. Su, and A. Iyengar, “Gradient-leakage resilient
federated learning,” in Proc. IEEE 41st Int. Conf. Distrib. Comput. Syst.
(ICDCS), Jul. 2021, pp. 797–807.
[25] J. Ma, S. Naas, S. Sigg, and X. Lyu, “Privacy-preserving federated
learning based on multi-key homomorphic encryption,” Int. J. Intell.
Syst., vol. 37, no. 9, pp. 5880–5901, 2022.
[26] I. Mustafa et al., “Noise free fully homomorphic encryption scheme
over non-associative algebra,” IEEE Access, vol. 8, pp. 136524–136536,
2020.
[27] J. Jentsch, A. B. ¨Unal, S ¸. S. Ma˘gara, and M. Akg ¨un, “Privacy preserving
data imputation via multi-party computation for medical applications,”
2024, arXiv:2405.18878.
[28] M. Rahaman, V . Arya, S. M. Orozco, and P. Pappachan, “Secure
multi-party computation (SMPC) protocols and privacy,” in Advances
in Information Security, Privacy, and Ethics . Hershey, PA, USA: IGI
Global, 2024, pp. 193–218.
[29] S. E. V . S. Pillai and K. Polimetla, “Enhancing network privacy through
secure multi-party computation in cloud environments,” in Proc. Int.
Conf. Integr. Circuits Commun. Syst. (ICICACS) , Feb. 2024, pp. 1–6.
[30] Y . Oh, N. Lee, Y .-S. Jeon, and H. V . Poor, “Communication-e ﬃcient
federated learning via quantized compressed sensing,” IEEE Trans.
Wireless Commun., vol. 22, no. 2, pp. 1087–1100, Feb. 2023.
[31] N. Lang, E. Sofer, T. Shaked, and N. Shlezinger, “Joint privacy
enhancement and quantization in federated learning,”IEEE Trans. Signal
Process., vol. 71, pp. 295–310, 2023.
[32] Y . Liu, S. Chang, and Y . Liu, “Cepe-FL: Communication-e ﬃcient and
privacy-enhanced federated learning via adaptive compressive sensing,”
IEEE Trans. Big Data , vol. 11, no. 5, pp. 2119–2134, Oct. 2025.
[33] L. Chen, D. Xiao, Z. Yu, and M. Zhang, “Secure and e ﬃcient federated
learning via novel multi-party computation and compressed sensing,”
Inf. Sci., vol. 667, May 2024, Art. no. 120481.
[34] H. Zhao, Y . Tan, K. Guo, W. Xia, B. Xu, and T. Q. S. Quek, “Client
scheduling for multiserver federated learning in industrial IoT with
unreliable communications,” IEEE Internet Things J. , vol. 11, no. 9,
pp. 16478–16490, May 2024.
[35] G. Rjoub, O. A. Wahab, J. Bentahar, R. Cohen, and A. S. Bataineh,
“Trust-augmented deep reinforcement learning for federated learning
client selection,” Inf. Syst. Frontiers , vol. 26, no. 4, pp. 1261–1278,
Aug. 2024.
[36] N. Dowlin, R. Gilad-Bachrach, K. Laine, K. Lauter, M. Naehrig, and
J. Wernsing, “CryptoNets: Applying neural networks to encrypted data
with high throughput and accuracy,” in Proc. Int. Conf. Mach. Learn. ,
2016, pp. 201–210.
[37] E. Hesamifard, H. Takabi, and M. Ghasemi, “CryptoDL: Deep neural
networks over encrypted data,” 2017, arXiv:1711.05189.
[38] H. Chabanne, A. De Wargny, J. Milgram, C. Morel, and E. Prou ﬀ,
“Privacy-preserving classiﬁcation on deep neural network,” IACR Cryp-
tol. ePrint Arch., 2017, vol. 2017, p. 35.
[39] C. Juvekar, V . Vaikuntanathan, and A. Chandrakasan, “GAZELLE: A
low latency framework for secure neural network inference,” in Proc.
27th USENIX Secur. Symp. (USENIX Security) , 2018, pp. 1651–1669.
[40] T. Li, A. K. Sahu, M. Zaheer, M. Sanjabi, A. Talwalkar, and V . Smith,
“Federated optimization in heterogeneous networks,” in Proc. Mach.
Learn. Syst., 2018, pp. 429–450.
[41] S. P. Karimireddy, S. Kale, M. Mohri, S. J. Reddi, S. U. Stich, and
A. T. Suresh, “SCAFFOLD: Stochastic controlled averaging for feder-
ated learning,” in Proc. Int. Conf. Mach. Learn. , 2019, pp. 5132–5143.
[42] J. Wang, G. Xu, W. Lei, L. Gong, X. Zheng, and S. Liu, “CPFL:
An e ﬀective secure cognitive personalized federated learning mecha-
nism for Industry 4.0,” IEEE Trans. Ind. Informat. , vol. 18, no. 10,
pp. 7186–7195, Oct. 2022.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 20

52376 IEEE INTERNET OF THINGS JOURNAL, VOL. 12, NO. 24, 15 DECEMBER 2025
[43] A. Ghosh, J. Chung, D. Yin, and K. Ramchandran, “An e ﬃcient
framework for clustered federated learning,” in Proc. Int. Conf. Neural
Inf. Proc. Sys. (NeurIPS) , 2020, pp. 19586–19597.
[44] B. Liu, Y . Guo, and X. Chen, “PFA: Privacy-preserving federated
adaptation for eﬀective model personalization,” in Proc. Web Conf., Apr.
2021, pp. 923–934.
[45] X. Huang, J. Liu, Y . Lai, B. Mao, and H. Lyu, “EEFED: Personalized
federated learning of execution & evaluation dual network for CPS intru-
sion detection,” IEEE Trans. Inf. Forensics Security, vol. 18, pp. 41–56,
2023.
[46] B. Li, Y . Wu, J. Song, R. Lu, T. Li, and L. Zhao, “DeepFed: Feder-
ated deep learning for intrusion detection in industrial cyber–physical
systems,” IEEE Trans. Ind. Informat. , vol. 17, no. 8, pp. 5615–5624,
Aug. 2021.
[47] T.-Y . Lin, P. Goyal, R. Girshick, K. He, and P. Doll ´ar, “Focal loss for
dense object detection,” in Proc. IEEE Int. Conf. Comput. Vis. (ICCV) ,
Oct. 2017, pp. 2980–2988.
[48] M. Hammoudeh, G. Epiphaniou, and P. Pinto, “Cyber-physical systems:
Security threats and countermeasures,” J. Sensor Actuator Netw., vol. 12,
no. 1, p. 18, Feb. 2023.
[49] J.-P.-A. Yaacoub, O. Salman, H. N. Noura, N. Kaaniche, A. Chehab,
and M. Malli, “Cyber-physical systems security: Limitations, issues and
future trends,” Microprocessors Microsyst., vol. 77, Sep. 2020, Art. no.
103201.
[50] R. Ji, D. Padha, Y . Singh, and S. Sharma, “Review of intrusion detec-
tion system in cyber-physical system based networks: Characteristics,
industrial protocols, attacks, data sets and challenges,” Trans. Emerg.
Telecommun. Technol., vol. 35, no. 9, p. 5029, Sep. 2024.
[51] S. C. Hassler, U. A. Mughal, and M. Ismail, “Cyber-physical intrusion
detection system for unmanned aerial vehicles,” IEEE Trans. Intell.
Transp. Syst., vol. 25, no. 6, pp. 6106–6117, Jun. 2024.
[52] R. Podschwadt, D. Takabi, and P. Hu, “SoK: Privacy-preserving deep
learning with homomorphic encryption,” 2021, arXiv:2112.12855.
[53] M. Sajid et al., “Enhancing intrusion detection: A hybrid machine and
deep learning approach,” J. Cloud Comput. , vol. 13, no. 1, p. 123, Jul.
2024.
[54] V . Bonagura, C. Foglietta, S. Panzieri, and F. Pascucci, “Advanced
intrusion detection system for industrial cyber-physical systems,” IFAC-
PapersOnLine, vol. 55, no. 40, pp. 265–270, 2022.
[55] P. Chhikara, R. Tekchandani, and N. Kumar, “Adaptive federated learn-
ing scheme for recognition of malicious attacks in an IoT network,”
Computing, vol. 106, no. 4, pp. 1177–1192, Apr. 2024.
[56] J. Li, X. Tong, J. Liu, and L. Cheng, “An e ﬃcient federated learning
system for network intrusion detection,” IEEE Syst. J. , vol. 17, no. 2,
pp. 2455–2464, Jun. 2023.
[57] M. Abdel-Basset, H. Hawash, K. M. Sallam, I. Elgendi, K. Munasinghe,
and A. Jamalipour, “Eﬃcient and lightweight convolutional networks for
IoT malware detection: A federated learning approach,” IEEE Internet
Things J., vol. 10, no. 8, pp. 7164–7173, Apr. 2023.
[58] O. Aouedi and K. Piamrat, “F-BIDS: Federated-blending based intrusion
detection system,” Pervas. Mobile Comput., vol. 89, Feb. 2023, Art. no.
101750.
[59] O. Friha, M. A. Ferrag, L. Shu, L. Maglaras, K.-K.-R. Choo, and
M. Nafaa, “FELIDS: Federated learning-based intrusion detection sys-
tem for agricultural Internet of Things,” J. Parallel Distrib. Comput. ,
vol. 165, pp. 17–31, Jul. 2022.
[60] N. A. Al-Athba Al-Marri, B. S. Ciftler, and M. M. Abdallah, “Federated
mimic learning for privacy preserving intrusion detection,” in Proc.
IEEE Int. Black Sea Conf. Commun. Netw. (BlackSeaCom) , May 2020,
pp. 1–6.
[61] A. Tabassum, A. Erbad, W. Lebda, A. Mohamed, and M. Guizani,
“FEDGAN-IDS: Privacy-preserving IDS using GAN and federated
learning,” Comput. Commun., vol. 192, pp. 299–310, Aug. 2022.
[62] G. Schram, R. Wang, and K. Liang, “Using autoencoders on di ﬀeren-
tially private federated learning GANs,” 2022, arXiv:2206.12270.
[63] M. M. Rashid, S. U. Khan, F. Eusufzai, M. A. Redwan, S. R. Sabuj,
and M. Elsharief, “A federated learning-based approach for improving
intrusion detection in industrial Internet of Things networks,” Network,
vol. 3, no. 1, pp. 158–179, Jan. 2023.
[64] S. A. Rahman, H. Tout, C. Talhi, and A. Mourad, “Internet of Things
intrusion detection: Centralized, on-device, or federated learning?,”
IEEE Netw., vol. 34, no. 6, pp. 310–317, Nov. 2020.
[65] Y .-C. Lai et al., “Two-phase defense against poisoning attacks on
federated learning-based intrusion detection,” Comput. Secur., vol. 129,
Jun. 2023, Art. no. 103205.
[66] J. Mei, X. Shen, C. Xu, L. Zhu, G. Jin, and K. Sharif, “Privacy-
preserving and robust federated learning based on secret sharing,” in
Proc. IEEE Int. Symp. Parallel Distrib. Process. With Appl. (ISPA), Oct.
2024, pp. 1643–1650.
[67] B. D. Manh, C.-H. Nguyen, D. T. Hoang, and D. N. Nguyen,
“Homomorphic encryption-enabled federated learning for privacy-
preserving intrusion detection in resource-constrained IoV networks,” in
Proc. IEEE 100th Veh. Technol. Conf. (VTC-Fall) , Oct. 2024, pp. 1–6.
[68] Z. A. E. Houda, A. S. Haﬁd, and L. Khoukhi, “MiTFed: A privacy
preserving collaborative network attack mitigation framework based on
federated learning using SDN and blockchain,” IEEE Trans. Netw. Sci.
Eng., vol. 10, no. 4, pp. 1985–2001, Jul. 2023.
[69] P. Verma, J. G. Breslin, and D. O’Shea, “FLDID: Federated learning
enabled deep intrusion detection in smart manufacturing industries,”
Sensors, vol. 22, no. 22, p. 8974, Nov. 2022.
[70] A. Albaseer and M. Abdallah, “Privacy-preserving honeypot-based
detector in smart grid networks: A new design for quality-assurance
and fair incentives federated learning framework,” in Proc. IEEE 20th
Consum. Commun. Netw. Conf. (CCNC) , Jan. 2023, pp. 722–727.
[71] Z. Ma, J. Ma, Y . Miao, Y . Li, and R. H. Deng, “ShieldFL: Mitigating
model poisoning attacks in privacy-preserving federated learning,” IEEE
Trans. Inf. Forensics Security, vol. 17, pp. 1639–1654, 2022.
[72] C. Zhang et al., “BatchCrypt: E ﬃcient homomorphic encryption for
cross-silo federated learning,” in Proc. USENIX Annu. Tech. Conf. ,
Boston, MA, USA, 2020, pp. 493–506.
[73] A. Reisizadeh, I. Tziotis, H. Hassani, A. Mokhtari, and R. Pedarsani,
“Straggler-resilient federated learning: Leveraging the interplay between
statistical accuracy and system heterogeneity,” IEEE J. Sel. Areas Inf.
Theory, vol. 3, no. 2, pp. 197–205, Jun. 2022.
[74] M. M. Taye, “Understanding of machine learning with deep learning:
Architectures, workﬂow, applications and future directions,” Computers,
vol. 12, no. 5, p. 91, Apr. 2023.
[75] Z.Ashraf,A.Sohail, andM.Yousaf, “Robust and lightweight symmet-
ric key exchange algorithm for next-generation IoE,” Internet Things ,
vol.22,2023, Art. no.100703.
[76] A. Ibarrondo and A. Viand, “Pyfhel: Python for homomorphic encryp-
tion libraries,” in Proc. 9th Workshop Encrypted Comput. Appl.
Homomorphic Cryptogr., Nov. 2021, pp. 11–16.
[77] A. Alsaedi, N. Moustafa, Z. Tari, A. Mahmood, and A. Anwar,
“TON IoT telemetry dataset: A new generation dataset of IoT and
IIoT for data-driven intrusion detection systems,” IEEE Access, vol. 8,
pp. 165130–165150, 2020.
[78] M. A. Ferrag, O. Friha, D. Hamouda, L. Maglaras, and H. Janicke,
“Edge-IIoTset: A new comprehensive realistic cyber security dataset of
IoT and IIoT applications for centralized and federated learning,” IEEE
Access, vol. 10, pp. 40281–40306, 2022.
[79] M. Al-Hawawreh, E. Sitnikova, and N. Aboutorab, “X-IIoTID: A
connectivity-agnostic and device-agnostic intrusion data set for indus-
trial Internet of Things,” IEEE Internet Things J. , vol. 9, no. 5,
pp. 3962–3977, Mar. 2022.
[80] P. Ruzafa-Alc ´azar et al., “Intrusion detection based on privacy-
preserving federated learning for the industrial IoT,” IEEE Trans. Ind.
Informat., vol. 19, no. 2, pp. 1145–1154, Feb. 2023.
Imtiaz Ali Soomro (Member, IEEE) received the
B.E. degree in telecommunications from Hamdard
University, Islamabad, Pakistan, in 2010, and the
M.S. degree in electrical engineering with a special-
ization in telecom and networking from COMSATS
University Islamabad, Islamabad, in 2012. He is
currently pursuing the Ph.D. degree in electrical
and computer engineering with the Sir Syed CASE
Institute of Technology, Islamabad.
His research interests are focused on the applica-
tion of federated learning for the Internet of Things
(IoT), wireless networks, and cybersecurity, particularly on privacy-preserving
technologies and secure communication in distributed systems.
Mr. Soomro is a member of IEEE, actively contributing to the research
community through his innovative work in machine learning, IoT, and
cybersecurity.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 21

ALI SOOMRO et al.: ROCHE: A ROBUST AND END-TO-END PPFL FRAMEWORK FOR INTRUSION DETECTION IN IIoT 52377
Hamood ur Rehman received the B.S. degree in
electronics engineering from the Ghulam Ishaq Khan
Institute of Technology, Topi, Swabi, Pakistan, in
2000, the M.S. degree in electrical engineering from
the University of Michigan, Ann Arbor, MI, USA, in
2005, and the Ph.D. degree in electrical engineering
from the King Fahd University of Petroleum and
Minerals, Dhahran, Eastern, Saudi Arabia, in 2019.
In his past experience, he has served as a
Senior Member of Technical Sta ﬀ at the Center
for Advanced Research and Engineering (CARE),
Islamabad, Pakistan, where he led projects ranging from the Internet of Things
(IoT) platform-as-a-service systems, cybersecurity products, and advanced
VLSI-based AI platforms for large language model (LLM) inference. From
2000 to 2003, he was a Senior VLSI Design Engineer with Avaz Networks
Inc., Irvine, CA, USA, working on high-density voice over IP (V oIP) system-
on-chips for gateway media switches. He worked as an Adjunct Professor with
the Department of Computer Science, Sir Syed CASE Institute of Technology,
Islamabad. He is currently an Assistant Professor with the Department of
Electrical Engineering, Habib University, Karachi, Pakistan. His primary
research interests are information theory and signal processing for networked
systems, such as wireless sensor networks (WSNs) and IoT.
Syed Jawad Hussain received the Ph.D. degree
in computer science from Massey University,
Palmerston North, New Zealand, in 2015, focusing
on developing high-deﬁnition video quality experi-
ence models.
He is currently an Associate Professor and the
Chairperson of the Sir Syed CASE Institute of
Technology, Islamabad, Pakistan. He has extensive
experience in academia and industry, having held
various leadership roles, including the Head of
Department positions at institutions in Pakistan and
abroad. He has worked on numerous research and consultancy projects, focus-
ing on machine learning, data security, and multimedia communications. He
has published extensively in prestigious journals and conferences, contributing
signiﬁcantly to the ﬁeld of computer science. His research interests include
multimedia communication networks, machine learning, quality of service
(QoS), quality of experience (QoE), data and network security, and statistical
modeling.
Sohaib Latif (Senior Member, IEEE) served as an
Assistant Professor, a Research Associate, and a
Lecturer nationally and internationally, with a robust
background in academia and research. In addition,
he serves as the CEO of EchoSoft Solution, a
company at the forefront of tech innovation. He has
over 11 years of excellent teaching and research
experience at several national and international uni-
versities. He is currently an Associate Professor
with the Department of Computer Science and Soft-
ware Engineering, Grand Asian University, Sialkot,
Pakistan. He has been publishing research articles extensively in prestigious
journals. His major research interests include machine learning, federated
learning, the Internet of Things (IoT), blockchain, and cybersecurity.
Hana Mujlid (Member, IEEE) received the
bachelor’s degree from the College of Science,
Faculty of Science, Umm Al-Qura University,
Makkah, Saudi Arabia, in 2005, and the M.Sc. and
Ph.D. degrees from Florida Institute of Technology,
Melbourne, FL, USA, in 2012 and 2016, respec-
tively.
She worked as a Computer Engineer with Com-
puter Technology Company in 2007. She also
worked as a Manager with the Communication and
Network Department, Umm Al-Qura University, in
2010. She enjoyed being a Mathematics Instructor at the Elementary School,
Ministry of Education, Saudi Arabia, in 2012. She worked as a Laboratory
Researcher at Florida Institute of Technology in 2016. She worked as the
Dean of the library at Taif University (TU), Taif, Saudi Arabia, from 2019
to 2021, and the Vice-Dean of the Society College in 2018. She is currently
working as the Head of the Computer Engineering Department, TU.
Syed Muhammad Mohsin received the B.S. and
M.S. degrees in computer science from the Virtual
University of Pakistan, Islamabad, Pakistan, in 2011
and 2016, respectively, and the Ph.D. degree in
computer science from COMSATS University Islam-
abad, Islamabad, in 2025.
He has worked as a Consultant and a Co-PI on
international research projects focusing on machine
learning and cybersecurity. He has published numer-
ous research papers in peer-reviewed conferences
and journals and presented his research work in
national and international conferences. His research interests include smart
grid, the Internet of Things, cloud computing, green energy, machine learning,
cyber security, and related areas.
Dr. Mohsin has been a TPC member and an invited reviewer for interna-
tional conferences and journals. He was a recipient of the Merit Scholarship
from the Higher Education Commission (HEC), Pakistan, for his Ph.D.
studies.
Carsten Maple was a co-investigator of the
PETRAS National Centre of Excellence for
the Internet of Things (IoT) Systems Cyber-
security. He is currently the Director of the
NCSC-EPSRC Academic Centre of Excellence
in Cyber Security Research and a Professor
of cyber systems engineering at the Univer-
sity of Warwick, Coventry, U.K. He is also
the Director of research innovation at EDGE-AI,
the National Edge Artiﬁcial Intelligence Hub, and
a fellow of the Alan Turing Institute, where he is a
Principal Investigator on U.S. $9 million project developing trustworthy digital
infrastructure. He is a co-investigator on the Framework for Responsible AI
in Finance project, leading on security and privacy. He has an international
research reputation, having published over 450 peer-reviewed articles. His
research has attracted millions of pounds in funding and has been widely
reported through the media.
Dr. Maple has given evidence to government committees on issues of
anonymity and child safety online. In addition, he has advised the boards of
public and multibillion-pound private sector organizations and is a member of
two royal society working groups, including the Working Group on Privacy
Enhancing Technologies.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:54:07 UTC from IEEE Xplore.  Restrictions apply.

