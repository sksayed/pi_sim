# KEM-22: An Efficient Post-Quantum ML-KEM Hardware Accelerator on 22-nm ASIC

- **Paper ID:** F
- **DOI:** https://doi.org/10.1109/jiot.2025.3635477
- **Source PDF:** `../pdf/KEM-22_An_Efficient_Post-Quantum_ML-KEM_Hardware_Accelerator_on_22-nm_ASIC_Paper_F.pdf`
- **Pages:** 12
- **Extracted:** auto via pypdf (layout/OCR not perfect; figures are not images)



---

## Page 1

IEEE INTERNET OF THINGS JOURNAL, VOL. 13, NO. 3, 1 FEBRUARY 2026 4715
KEM-22: An E ﬃcient Post-Quantum ML-KEM
Hardware Accelerator on 22-nm ASIC
Stefano Di Matteo
 , Ivan Sarno
 , Emanuele Valea
 , and Sergio Saponara
 , Senior Member , IEEE
Abstract—This article presents a performant and compact
hardware accelerator for the module-lattice key encapsulation
mechanism (ML-KEM) algorithm, compliant with the NIST
FIPS 203 speciﬁcation and implemented in a 22-nm ASIC
technology. The proposed design supports all three standardized
security levels (ML-KEM-512, -768, and -1024) using a uniﬁed,
parameter-agnostic architecture that avoids logic duplication.
The design relies exclusively on SRAM blocks for storage,
completely eliminating FIFOs and intermediate bu ﬀers, while
ﬂip-ﬂops are used only in timing-critical paths to achieve high-
frequency operation with minimal area overhead. Among all
known ASIC implementations, our architecture achieves the
best normalized area–time product (ATP) across all ML-KEM
parameter sets, demonstrating e ﬃciency and scalability while
also delivering the lowest power and energy per operation among
state-of-the-art solutions. These results make the proposed design
a strong candidate for real-world post-quantum cryptographic
deployments on constrained hardware and IoT platforms.
Index Terms—ASIC, CRYSTALS-Kyber, fully depleted silicon
on insulator (FD-SOI), module-lattice key encapsulation mecha-
nism (ML-KEM), post-quantum cryptography (PQC).
I. I NTRODUCTION
T
HE rapid advancement of quantum computing threatens
the security foundations of widely deployed public-key
cryptosystems, such as RSA and elliptic curve cryptography
(ECC) [1]. Algorithms like Shor’s and Grover’s demonstrate
that once scalable quantum computers are available, these
classical schemes will no longer provide adequate protection
for secure communications [2].
In 2016, U.S. National Institute of Standards and Technol-
ogy (NIST) launched the post-quantum cryptography (PQC)
standardization process [3]. In 2024, this process culminated
in the publication of the ﬁrst three PQC standards, namely,
module-lattice key encapsulation mechanism (ML-KEM) [4],
ML-DSA [5], and SLH-DSA [5]. Speciﬁcally, the ML-KEM,
formerly known as CRYSTALS-Kyber [6], is the only KEM
that is actually standardized.
Despite its algorithmic e ﬃciency, the practical deploy-
ment of ML-KEM in real-world systems remains challenging,
Received 2 September 2025; revised 20 October 2025 and 6 November
2025; accepted 18 November 2025. Date of publication 20 November 2025;
date of current version 26 January 2026. This work was supported in part
by France 2030 Program under Grant ANR-22-PETQ-0008 PQ-TLS and in
part by the European Union (EU) Horizon 2020 Project “European Processor
Initiative” (EPI SGA2) under Grant 101036168. (Corresponding author:
Stefano Di Matteo.)
Stefano Di Matteo is with CEA-Leti, Univ. Grenoble Alpes, 38000 Greno-
ble, France, and also with CEA-List, Univ. Grenoble Alpes, 38000 Grenoble,
France (e-mail: stefano.dimatteo@cea.fr).
Ivan Sarno and Emanuele Valea are with CEA, List, Univ. Grenoble Alpes,
38000 Grenoble, France.
Sergio Saponara is with the Department of Information Engineering,
University of Pisa, 56122 Pisa, Italy.
Digital Object Identiﬁer 10.1109 /JIOT.2025.3635477
particularly on constrained platforms such as embedded
devices, IoT nodes, and edge processors [7]. These envi-
ronments require hardware accelerators that achieve high
performance while minimizing memory usage, silicon area,
and energy consumption [8].
Though most of the research in this ﬁeld has focused on
FPGA implementations, a signiﬁcant body of work in the
past few years has investigated hardware implementations
of ML-KEM on ASICs. Some of these accelerators achieve
compact area footprints but lack scalability across the diﬀerent
security levels (i.e., ML-KEM-512 /768/1024) [9], [10], [11],
[12]. Others provide reconﬁgurable or uniﬁed support, but at
the cost of substantial silicon overheads due to duplicated
logic and wide datapaths [13], [14], [15], [16]. As a result, no
existing design achieves an optimal balance of conﬁgurability,
eﬃciency, and throughput.
In this article, we address these limitations by present-
ing KEM-22, a novel hardware accelerator for ML-KEM
implemented on a 22-nm fully depleted silicon on insula-
tor (FD-SOI) ASIC technology. The proposed architecture
supports all standardized security levels through a uniﬁed,
parameter-agnostic datapath, eliminating the need for hard-
ware duplication. Our design further minimizes area by relying
exclusively on compact SRAM blocks, employing registers
only in timing-critical paths to sustain a high operating fre-
quency. As a result, KEM-22 achieves the best normalized
area–time product (ATP) reported to date, surpassing all
prior ASIC implementations. In addition, this architecture
is particularly well-suited for constrained environments and
Internet of Things (IoT) devices, where silicon area, power
eﬃciency, and multilevel cryptographic support are critical.
Compared to the state of the art, our design delivers superior
performance–eﬃciency tradeoﬀs, enabling secure, lightweight
PQC in highly resource-limited systems. The main contribu-
tions of this article are summarized as follows.
1) We introduce KEM-22, a hardware accelerator that
supports all three standardized ML-KEM security levels
(512, 768, and 1024) within a single uniﬁed datapath,
avoiding hardware duplication while preserving consis-
tent eﬃciency across modes.
2) Our accelerator relies exclusively on compact SRAM
blocks for storage, eliminating FIFOs and intermediate
buﬀers. We use registers only in timing-critical paths,
which enable very high operating frequencies with min-
imal area overhead.
3) Compared to state-of-the-art ASIC implementations,
our design achieves the lowest normalized ATP
across all ML-KEM levels, delivering superior
performance–eﬃciency tradeo ﬀs well-suited for
2327-4662 © 2025 IEEE. All rights reserved, including rights for text and data mining, and training of artiﬁcial intelligence and
similar technologies. Personal use is permitted, but republication /redistribution requires IEEE permission.
See https://www.ieee.org/publications/rights/index.html for more information.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 2

4716 IEEE INTERNET OF THINGS JOURNAL, VOL. 13, NO. 3, 1 FEBRUARY 2026
silicon- and power-constrained systems such as IoT
nodes.
The remainder of this article is organized as follows. Sec-
tion II reviews the cryptographic foundations of ML-KEM
and its underlying computational building blocks. Section III
surveys the state of the art in hardware accelerators for
Kyber/ML-KEM and highlights their main limitations. Sec-
tion IV introduces the proposed KEM-22 architecture in detail,
while Section V reports implementation results and compares
them with existing works. Finally, Section VI concludes the
work.
II. ML-KEM C RYPTOSYSTEM
The ML-KEM cryptosystem relies on asymmetric cryptog-
raphy to establish a shared secret between two parties. The
shared secret can be used, for instance, to set a conﬁdential
communication between the two parties protected by symmet-
ric cryptography. KEMs are based on a public-key encryption
(PKE) system that is composed of three functions, deﬁned as
follows.
1) Key Generation (PKE.KeyGen): It generates a public key
(pk) and a secret key (sk). A random seed ( d) is set as
input of the function for randomizing the generation of
the keys over multiple executions.
2) Encryption (PKE.Encrypt): It takes as input a message
(m) and the public key (pk). It generates a ciphertext ( c).
A random nonce ( r) can be used as additional input for
randomizing the execution of the function over multiple
executions with the same inputs.
3) Decryption (PKE.Decrypt): It takes as inputs the
ciphertext ( c) and the secret key (sk). It outputs the
message ( m).
Let us suppose a scenario in which two parties, say Alice
and Bob, want to exchange a secret key. Alice starts by
executing the PKE.KeyGen function and sends the public key
to Bob. Then, Bob encrypts the message using the public key
and sends the ciphertext to Alice. Finally, Alice performs the
decryption function and retrieves the message. At this point,
the same message is exclusively known by Alice and Bob,
making it a shared secret.
PKE systems provide a level of security that is called IND-
CPA (i.e., Indistinguishable under Chosen Plaintext Attacks).
In a nutshell, this means that an attacker is not able to learn
secret information only relying on the knowledge of validly
generated ciphertexts. However, IND-CPA security leaves the
door open to attacks that involve crafting corrupted ciphertexts
that are decrypted using the secret key. These kinds of attacks
are called Adaptive Chosen Ciphertext Attacks . The KEM is
constructed by wrapping the PKE functions with an upper
layer, called Fujisaki–Okamoto (FO) transform, that grants
IND-CCA2 (i.e., Indistinguishable under Adaptive Chosen
Ciphertext Attacks) security.
A. KEM Functions in ML-KEM
The external interface of ML-KEM is made of the three
KEM functions that are shown in Algorithms 1–3.
1) Key Generation (KEM.KeyGen): This function gener-
ates, at ﬁrst, two random seeds d and z. Then, the
PKE.KeyGen function is executed, using the seed d as
input. Finally, the public key pk and the secret key sk are
generated from the output of the PKE.KeyGen function.
The FO transform necessitates that the ﬁnal secret key
contains, besides sk′, also the public key pk, a hash of
the public key ( h), and the random value z.
2) Encapsulation (KEM.Encaps): This function generates,
at ﬁrst, a random message m. A random nonce r and the
shared secret K are both generated through a hash of the
message and the public key. After that, the PKE.Encrypt
function is executed, generating the ciphertext c.
Algorithm 1 KEM.KeyGen()
1: Output: Public key pk, secret key sk
2: Draw seeds d, z
3: (pk′, sk′) = PKE.KeyGen(d)
4: pk = pk′
5: h = SHA3-256(pk)
6: sk= (sk′‖pk‖h‖z)
7: return (pk, sk)
Algorithm 2 KEM.Encaps(pk)
1: Input: Public key pk
2: Output: Shared secret K, ciphertext c
3: Draw seed m
4: (K, r) = SHA3-512(m‖SHA3-256(pk))
5: c = PKE.Encrypt(pk, m, r)
6: return (K, c)
Algorithm 3 KEM.Decaps(sk,c)
1: Input: Secret key sk, ciphertext c
2: Output: Shared secret K
3: (sk′, pk, h, z) = sk
4: m′ = PKE.Decrypt(sk′, c)
5: (K′, r′) = SHA3-512(m′‖h)
6: c′ = PKE.Encrypt(pk, m′, r′)
7: ¯K = SHAKE-256(z‖c)
8: if c′ = c then
9: return K′
10: else
11: return ¯K
12: end if
3) Decapsulation: This function contains most of the over-
head due to the FO transform. First, the ciphertext c
is deciphered through the PKE.Decrypt function, using
the secret key sk. A candidate message m′ is retrieved.
This allows to compute a candidate shared secret K′.
However, in order to verify that the input ciphertext
is valid, it is necessary to recompute the PKE.Encrypt
function on m′ and check whether the computed cipher-
text c′ is equal to the input one. If this is the case, K′
can be returned as the ﬁnal shared secret. Otherwise,
a random conﬁdential value z is returned as an invalid
shared secret.
It can be observed that the core of ML-KEM lies in the
PKE functions. These functions account for the majority of
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 3

MATTEO et al.: EFFICIENT POST-QUANTUM ML-KEM HARDW ARE ACCELERATOR ON 22-nm ASIC 4717
TABLE I
ML-KEM K EYS AND CIPHERTEXT SIZES (B YTES )
the computational complexity in ML-KEM. As shown in
Algorithms 1–3, operations outside the PKE functions are
limited to calls to hash functions, which are implemented using
the SHA-3 standard [17].
B. PKE Functions in ML-KEM
Before delving into the details of the PKE functions, it
is necessary to understand the mathematical formalism on
which ML-KEM stands from a cryptographic point of view.
The security of ML-KEM relies on a variant of the learning
with errors (LWE) problem. The LWE problem consists in
ﬁnding the solution of a system of linear equations with
noisy coe ﬃcients. More formally, let us consider a secret
vector s with elements in Zq (i.e., the set of integer values
modulo q). Given a matrix A of elements in Zq and a vector
b = As + e, such that A is randomly sampled in Zq and e
is sampled by a discrete Gaussian distribution, ﬁnding the
values of s is considered hard even for a quantum computer.
ML-KEM is based on a variant of the LWE problem, called
module LWEs (M-LWEs), where matrices and vectors in Zq
are replaced by matrices and vectors of polynomials in the
ring Rq = Zq[x]/(Xn + 1). This corresponds to polynomials
with n coeﬃcients, where each coe ﬃcient lies in the interval
[0, q−1]. In ML-KEM, n and q are constant such that n = 256
and q = 3329.
ML-KEM can be implemented according to three di ﬀerent
security levels, namely, ML-KEM-512, ML-KEM-768, and
ML-KEM-1024. The main parameter that deﬁnes the security
level is the k parameter, which corresponds to the size of
the matrices and vectors of polynomials that are manipulated
in the algorithm. k is equal to 2 in ML-KEM-512 (i.e.,
meaning that each vector is made of two polynomials, thus
512 coe ﬃcients), to 3 in ML-KEM-768, and to 4 in ML-
KEM-1024. This has an impact on the sizes of the keys and
the ciphertext, as shown in Table I.
The PKE functions of ML-KEM are shown in
Algorithms 4–6. The computations involved in these
functions can be grouped into three main categories.
1) Sampling Functions : These are used within the
PKE.Keygen and PKE.Encrypt functions to generate
the polynomials required for the M-LWE operations.
Two types of sampling are employed: uniform sampling,
carried out by the Sample U function, and sampling from
the centered binomial distribution (CBD), implemented
by the Sample CBD function. In both cases, sampling
begins with the initialization of a pseudorandom number
generator (PRNG) using a seed (e.g., the seed ρ in
SampleU during key generation). The PRNG is typi-
cally instantiated using the SHAKE functions from the
SHA-3 family, as speciﬁed by the FIPS 202 standard,
Algorithm 4 PKE.KeyGen(d)
1: Input: Random seed d
2: Output: Public key pk, secret key sk
3: (ρ,σ ) = SHA3-512(d)
4: ˆA = SampleU(ρ)
5: (s, e) = SampleCBD(σ)
6: ˆs = NTT(s)
7: ˆe = NTT(e)
8: ˆt = ˆA· ˆs + ˆe
9: pk = Encode(ˆt‖ρ)
10: sk = Encode(ˆs)
11: return (pk, sk)
Algorithm 5 PKE.Encrypt(pk,m,r)
1: Input: Public key pk, message m, random seed r
2: Output: Ciphertext c
3: (ˆt,ρ ) = Decode(pk)
4: ˆA = SampleU(ρ)
5: (y, e1, e2) = SampleCBD(r)
6: ˆy = NTT(y)
7: u = INTT( ˆA
⊤
· ˆy) + e1
8: µ = Decompress(Decode(m))
9: v = INTT(ˆt
⊤
· ˆy) + e2 +µ
10: c1 = Encode(Compress(u))
11: c2 = Encode(Compress(v))
12: return c = (c1‖c2)
Algorithm 6 PKE.Decrypt(sk,c)
1: Input: Secret key sk, ciphertext c
2: Output: Message m
3: (c1, c2) = c
4: u = Decompress(Decode(c1))
5: v = Decompress(Decode(c2))
6: ˆs = sk
7: w = v− INTT(ˆs⊤· NTT(u))
8: return m = Encode(Compress(w))
and it outputs uniformly distributed random bytes. These
bytes are then processed by the sampling functions. In
the case of Sample U, a rejection sampling method is
applied to select values in the range [0 , q− 1], while
SampleCBD produces noise and secret values following
a binomial distribution.
2) Polynomial Functions : These functions perform opera-
tions on matrices and vectors of polynomials, primarily
polynomial multiplications. Such multiplications are car-
ried out in the ring Rq and are e ﬃciently implemented
using the number theoretic transform (NTT), which
reduces the computational complexity of polynomial
multiplication from O(n2) to O(n log n). More details on
the NTT are provided in Section II-C.
3) Encode/Decode Functions: These functions are used for
serializing and deserializing structured objects (polyno-
mials, vectors, ciphertexts, and keys) into ﬁxed-length
byte strings and back.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 4

4718 IEEE INTERNET OF THINGS JOURNAL, VOL. 13, NO. 3, 1 FEBRUARY 2026
Fig. 1. Butterﬂy units for the NTT according to the CT and GS conﬁgurations.
4) Compression/Decompression Functions : These func-
tions are employed for compressing the ciphertext
and processing the message during encryption and
decryption. The Compress q(x, d) function maps an ele-
ment x ∈ Zq to an integer in the range [0 , 2d− 1].
Conversely, the Decompress q function reconstructs an
element x∈ Zq that closely approximates the original
value before compression.
C. Polynomial Arithmetic and NTT-Based Multiplication
Polynomial multiplication of (n−1)-degree polynomials can
be e ﬃciently implemented using NTT-based multiplication,
with O(n log n) complexity. The forward NTT converts an
(n− 1)-degree polynomial, in coe ﬃcient representation, into
n constant polynomials in value representation (i.e., NTT
domain). In this domain, polynomial multiplication becomes
a simple point-wise multiplication (PWM) with linear com-
plexity. The inverse NTT (INTT) is applied to the result
for returning to the coe ﬃcient representation. The NTT is
typically computed using butterﬂy operations organized in
either the Cooley–Tukey (CT) or Gentleman–Sande (GS)
conﬁgurations [18], as shown in Fig. 1.
In ML-KEM, the NTT structure must be adapted to the
algebraic properties of the underlying ring. The ﬁeld Zq, with
q = 3329, does not contain a 2nth primitive root of unity; thus,
the polynomial modulus ( Xn + 1) cannot be fully factored into
n degree-1 polynomials, but rather into n/2 degree-2 polyno-
mials [4]. As a result, a 256-term NTT is performed as two
separate 128-term NTTs, and the PWM is adapted accordingly.
Some details on the hardware implementation strategy for NTT
can be found in [19]. The PWM of two polynomials, already
in the NTT domain, is denoted as ˜h = PWM( ˜f, ˜g) and it is
computed as follows:
˜h [i] = ˜f [i]· ˜g [i] =
  ˜f2i+1X + ˜f2i

·
 
˜g2i+1X + ˜g2i

. (1)
This can be evaluated using ﬁve modular multiplications and
two modular additions at the end(
˜h2i = ˜f2i· ˜g2i + ˜f2i+1· ˜g2i+1·ωrev(n/22i+1)
˜h2i+1 = ˜g2i· ˜f2i+1 + ˜f2i· ˜g2i+1. (2)
Thus, the PWM of two polynomials with n coeﬃcients can be
performed by applying (2) for n/2 iterations.
III. S TATE OF THE ART
Over the past years, several hardware implementations
on ASIC technologies of ML-KEM, or its previous version
CRYSTALS-Kyber, have been proposed. The work in [9] is
one of the smallest ASIC implementations available for Kyber.
It employs a half-folded Keccak core for the implementation
of the SHA-3 functions and it contains memory optimizations.
The authors claim a reduction of the hardware footprint to
253 kilo gate equivalent (kGE) with only 7 kB of memory
while achieving a full Kyber-512 KEM execution in 21 143
clock cycles at 270 MHz (i.e., 78 µs) on a 40-nm technol-
ogy. However, this design has some limitations. It supports
only the Kyber-512 parameter set, lacking conﬁgurability for
higher security levels. This restricts its use to low-security
environments. Additionally, the implementation is not aligned
with the ML-KEM standard.
The accelerator in [10] provides an e ﬃcient perfor-
mance/area balance, achieving a full Kyber-512 KEM exe-
cution in only 9506 cycles, which is notably faster than
comparable designs, with an area footprint of 302 kGE,
including 9 kB of memory. It achieves an operating frequency
up to 180 MHz on a 40-nm technology, resulting in a latency
of 53 µs. The design incorporates reconﬁgurable arithmetic
units and isolated memory to support secure operations. While
the architecture is promising in terms of speed and area, the
main limitation is the limited support to Kyber-512.
Bisheh-Niasar et al. [12] propose a solution with remarkable
area e ﬃciency for Kyber-512. The proposed design only
consumes 222 kGE while achieving a total execution time of
83.9µs at 200 MHz. However, a key limitation of the proposed
architecture lies in its lack of scalability across di ﬀerent
security levels without duplicating hardware resources. In fact,
each security level necessitates a dedicated instantiation of the
accelerator tailored to its respective polynomial vector size. As
a result, the gate count increases signiﬁcantly at high security
levels. For example, Kyber-1024 demands 409 kGE, nearly
doubling the area footprint. This absence of architectural
reusability across parameter sets may hinder the practicality
of deploying this design in constrained environments, where
support for multiple security levels is desirable within a single
hardware proﬁle.
The work presented by Aikata et al. [13] introduces KaLi,
a uniﬁed cryptoprocessor architecture tailored to support all
security levels of both CRYSTALS-Kyber and CRYSTALS-
Dilithium. The architecture is notable for its high performance,
instruction-set ﬂexibility, and full algorithmic coverage, mak-
ing it one of the ﬁrst comprehensive ASIC designs to support
a complete cryptographic protocol suite in a single proces-
sor. Operating at a clock frequency of 1 GHz on a 28-nm
technology, KaLi achieves a latency of only 34 µs for Kyber-
768. However, this strong performance comes with important
tradeoﬀs in area and memory consumption. KaLi reaches
an area of 747 kGE, which is relatively large compared to
domain-speciﬁc or Kyber-only implementations. This increase
in area is attributable to the uniﬁed support for Dilithium,
which requires 23-bit wide datapaths and more complex sam-
pling and compression units, inﬂating both logic and memory
footprints.
Zhao et al. [14] introduce a highly optimized domain-
speciﬁc processor for Module-LWE-based schemes, focusing
on accelerating CRYSTALS-Kyber and CRYSTALS-Dilithium
through a custom matrix extension of the RISC-V ISA. The
standout achievement of this work is its exceptional perfor-
mance, reaching around 6000 clock cycles for Kyber-512 and
around 12 000 cycles for Kyber-1024. The implementation
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 5

MATTEO et al.: EFFICIENT POST-QUANTUM ML-KEM HARDW ARE ACCELERATOR ON 22-nm ASIC 4719
runs at 540 MHz on a TSMC 28-nm technology, thus achiev-
ing a latency of 11 µs for Kyber-512. Despite its outstanding
speed, the design exhibits notable area and memory overheads.
The processor consumes 623 kGE and 36.75 kB of SRAM
memory, which is signiﬁcantly higher than implementations
dedicated solely to Kyber.
The work by Li et al. [11] presents a specialized imple-
mentation of Kyber-512 targeting a 40-nm technology. The
execution time is around 12 200 clock cycles. The design
includes secure and public memory isolation, a ﬂexible mod-
ular arithmetic pipeline, and a conﬁgurable SHA-3-based
data generator to support rejection and binomial sampling.
However, this performance comes at the cost of signiﬁcant
silicon area usage, consuming 532 kGE. Additionally, the
maximum frequency is limited to 115 MHz, resulting in a
latency of 106 µs for Kyber-512.
To the best of our knowledge, the most recent ASIC imple-
mentation of ML-KEM is the one in [15], which proposes
an accelerator for all the security levels, targeting a 180-nm
technology. It performs a full KEM in 7.7k, 12.3k, and 17.2k
clock cycles for, respectively, ML-KEM-512, ML-KEM-768,
and ML-KEM-1024. The area consumption is estimated to
160 kGE, plus 7.37 kB of RAM. Unfortunately, the authors
did not report the complete area consumption in kGE, which
makes a direct comparison impossible to be done.
Despite the considerable research e ﬀorts devoted to hard-
ware acceleration of ML-KEM /Kyber, existing ASIC designs
still present notable limitations when it comes to simulta-
neously achieving conﬁgurability, area e ﬃciency, and per-
formance across all security levels. Several works focus
exclusively on Kyber-512, oﬀering optimized performance and
minimal area usage. However, these designs lack scalability
to higher security levels (e.g., Kyber-768 and Kyber-1024) or
require distinct hardware instantiations for each level, leading
to a rapid increase in silicon area and logic duplication. On
the other end of the spectrum, uniﬁed architectures support
a broader algorithmic suite (e.g., Kyber and Dilithium), but
they incur signiﬁcant area overheads, largely due to wide
datapaths, complex control logic, and duplicated resources for
diﬀerent primitives. Notably, only one recent implementation,
in [15], claims support for all ML-KEM levels, but it lacks
a complete breakdown of area ﬁgures, making it hard to
benchmark its actual e ﬃciency or to assess its suitability for
constrained environments. Furthermore, while execution times
are promising, the architecture details remain too high level
to evaluate its resource-sharing strategies or its modularity.
To the best of our knowledge, a uniﬁed and low-area
ASIC accelerator for ML-KEM that supports all three security
levels (ML-KEM-512/768/1024)—while preserving high per-
formance, low memory usage, and a modest logic footprint—is
still missing from the literature. We argue that such a design
is feasible by carefully leveraging logic resource sharing (e.g.,
using shared memory blocks instead of FIFO bu ﬀers), conﬁg-
urable datapaths, and register-based pipelining optimized for
frequency scaling without heavily inﬂating area. The proposed
approach aims to maximize hardware reusability across poly-
nomial dimensions, providing a single hardware proﬁle that
scales across all ML-KEM levels without instantiating separate
logic blocks for each parameter set.
IV. P ROPOSED ACCELERATOR FOR ML-KEM
Key architectural decisions in the design of KEM-22 are
guided by two main considerations: minimizing memory
usage—due to its substantial impact on overall area—and
reducing the communication overhead between the accelerator
and the main processor, and among the internal subblocks of
the accelerator, which can signiﬁcantly degrade performance
during ML-KEM execution. To address these challenges, the
architecture adopts a memory-e ﬃcient design strategy that
relies exclusively on RAM-based storage. In particular, it
avoids the use of queues or dedicated registers for storing poly-
nomials, thereby signiﬁcantly lowering the area footprint. The
memory system is organized around a single main memory
block, which handles both input and output data, and two addi-
tional memory blocks dedicated to intermediate polynomial
computations. This streamlined memory hierarchy not only
improves area e ﬃciency but also simpliﬁes data management
and access patterns within the accelerator, contributing to
a more balanced and high-performance design. The overall
architecture of the accelerator, depicted in Fig. 2, is organized
into six core modules, each responsible for a distinct aspect
of computation or control.
1) Interface RAM: The Interface RAM serves as the main
memory of the accelerator. It stores all the input and
output data required for the computation of intermediate
functions of ML-KEM.
2) Polynomial Unit: This module is dedicated to perform
polynomial computations, including NTT, INTT, PWM,
addition/subtraction, and polynomial multiplication.
3) Generation Unit: This module is responsible for gen-
erating polynomials from a given seed and performing
hashing operations. It is composed of two submodules,
each dedicated to a speciﬁc task.
a) Sampling Core: This submodule handles the sam-
pling of polynomial coe ﬃcients from CBD and
rejection sampling.
b) Keccak Core: This submodule executes the SHA-3
and SHAKE algorithms.
4) Encode Unit: This module encodes the polynomial coef-
ﬁcients produced by the polynomial unit in an e ﬃcient
representation and stores them in the Interface RAM.
5) Decoding Unit : The decoding unit is responsible for
decoding polynomials that are stored in a compressed
form within the Interface RAM. This module reverses
the encoding process, allowing the system to retrieve
and utilize the original polynomial coe ﬃcients.
6) Control Unit: This module is the central control unit of
the accelerator, responsible for decoding the incoming
commands and coordinating the operations of the other
submodules.
The KEM-22 accelerator executes the three main functions
of the ML-KEM protocol (i.e., KEM.KeyGen, KEM.Encaps,
and KEM.Decaps), with all the supported security levels
(i.e., ML-KEM-512/-768/-1024).
A. Polynomial Unit
The polynomial unit features a memory section composed
of two dual-port RAMs to store polynomial coe ﬃcients and
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 6

4720 IEEE INTERNET OF THINGS JOURNAL, VOL. 13, NO. 3, 1 FEBRUARY 2026
TABLE II
DKU O PERATIONS AND THEIR PERFORMANCE , IN CLOCK CYCLES
Fig. 2. General architecture of the KEM-22 accelerator.
Fig. 3. DKU implementation to support PWM only.
one read-only memory (ROM) for twiddle factors, and an
arithmetic logic unit (ALU) named dual KEM-22 unit (DKU),
which performs operations on the polynomial coe ﬃcients.
1) Dual KEM-22 Unit: The DKU includes the arithmetic
and logic resources to support the operations reported in
Table II, in particular, the NTT in CT conﬁguration, the
INTT in GS conﬁguration, the PWM, and the polynomial
addition. Along with this, we also included three operations
(i.e., MONT-ADD, CMUL-ADD, and CMUL-SUB), which
consist in multiplication by a constant followed by polynomial
addition or subtraction. The reported clock cycles remain
identical across all considered security levels.
The PWM is one of the most complex operations in ML-
KEM, as explained in Section II-C and shown in (2). The
PWM operation involves ﬁve multiplications: four between
adjacent coe ﬃcients from the two input polynomials and
one with a twiddle factor, along with two additions. This
operation produces two adjacent output coeﬃcients. Instead of
optimizing the DKU for the NTT as is common in most imple-
mentations in the literature, we designed our DKU around the
PWM operation, targeting the generation of one coe ﬃcient
per clock cycle. The hardware architecture of our DKU for
PWM is illustrated in Fig. 3. The PWM operation is divided
into two sequential rounds that share common input data. The
ﬁrst round, which computes the ˆh2i coeﬃcient, involves two
multiplications plus an additional multiplication with twiddle
factors. As a result, it features a longer pipelined datapath
compared to the second round (i.e., one clock cycle more).
The second round computes the ˆh2i+1 coeﬃcient using only
two multiplications and a shorter datapath. This design allows
both output coe ﬃcients to be generated simultaneously while
maintaining a consistent word size across input and output
interfaces. As shown in Fig. 3, the pipeline is eﬃciently imple-
mented using three multipliers and completes a full PWM
operation in 261 clock cycles. The Montgomery reduction
submodule is implemented using a shift-and-add multiplier,
and the reduction step following additions is optimized by
assuming that the intermediate result exceeds the modulus
at most once. This approach eliminates the need for a more
expensive Barrett reduction. Starting from the architecture of
Fig. 3 for PWM, we extended its capabilities in order to
support butterﬂy computations in CT and GS conﬁgurations.
The ﬁnal architecture of the DKU is depicted in Fig. 4.
Building on the original PWM architecture, we introduced
two subtractor units—highlighted in the dashed blue box—to
support the NTT in CT conﬁguration. Additionally, to enable
the INTT in GS conﬁguration, we added two subtractors and
two adders, as shown in the dashed red box of Fig. 4. The
INTT requires a ﬁnal multiplication by a correction factor
(i.e., n−1 mod q) for all coe ﬃcients after the last round. To
maintain the same throughput as the NTT—without extending
the pipeline or adding extra logic—we opted to perform this
ﬁnal multiplication separately. This ensures that the control
logic of the INTT remains aligned with that of the NTT.
In ML-KEM, the INTT is always followed by a polynomial
addition or subtraction. To optimize this, we combined the
ﬁnal correction multiplication with the subsequent operation,
resulting in two new operations: CMUL-ADD and CMUL-
SUB, which leverage the existing datapath resources of the
DKU. Similarly, the MONT-ADD operation multiplies each
coeﬃcient of a polynomial by a ﬁxed constant (i.e., the
Montgomery constant). Since this is always followed by an
addition, we merged the two steps: MONT-ADD now multi-
plies each coeﬃcient of the ﬁrst operand by the ﬁxed constant
and adds the corresponding coe ﬃcient of the second operand.
We also implemented polynomial addition in the DKU by
reusing existing hardware resources. All the aforementioned
operations—involving polynomial addition or constant multi-
plication followed by addition /subtraction—are completed in
132 clock cycles.
2) Memory Layout: The polynomial unit is composed of
two banks of dual-port RAMs, each with a word size of 26 bits,
allowing them to store two coe ﬃcients per memory row. In
addition, a single-port ROM is used to store the precomputed
twiddle factors and constants. As illustrated in Fig. 2, DP-
RAM0 can store up to ﬁve polynomials and is accessible by
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 7

MATTEO et al.: EFFICIENT POST-QUANTUM ML-KEM HARDW ARE ACCELERATOR ON 22-nm ASIC 4721
Fig. 4. Architecture of the DKU. Dashed red boxes indicate hardware resources allocated to the INTT (GS conﬁguration), dashed blue boxes represent
resources for the NTT (CT conﬁguration), and dashed green boxes correspond to those used for PWM.
Fig. 5. Flow of the vector–vector multiplication and error addition ( ˆai ˆsi + ˆe0).
the encode unit for reading, while DP-RAM1 can store two
polynomials and is used by the generation and decoding units
for writing. The size of DP-RAM0 is 2 kB, while DP-RAM1
is 0.8 kB.
To implement NTT and INTT, we adopted a ping-pong
strategy instead of an in-place design. In the ping-pong
approach, one RAM is used for reading and the other for
writing during each stage of the transform, alternating their
roles after each stage. This method simpliﬁes control logic,
avoids the complexity of handling data reordering and memory
conﬂicts, and ﬁts well within our architecture, which already
includes enough memory to hold multiple polynomials. As
a result, the beneﬁts of using an in-place design—mainly
memory savings—are not signiﬁcant in our case. Additionally,
using two separate RAMs enables the parallel execution of
tasks such as polynomial encoding and sampling. The speciﬁc
conﬁguration of ﬁve slots in DP-RAM0 and two in DP-RAM1
is needed to support the most demanding case: the ˆAˆs + ˆe
operation in ML-KEM-1024, as illustrated in Fig. 5.
The process starts by sequentially writing the secret polyno-
mials si into DP-RAM1. Each polynomial is then transformed
into the NTT domain, becoming ˆ si, using a ping-pong strat-
egy that alternates memory accesses between DP-RAM1 and
DP-RAM0 at each stage of the transformation. Upon com-
pletion of the NTT, the transformed polynomial is stored in
DP-RAM0. This procedure is repeated for all four polynomials
composing s. Next, the public matrix polynomials ˆ ai are
streamed into DP-RAM1, one at a time. Each polynomial
is ﬁrst written into DP-RAM1 and then multiplied with the
corresponding ˆsi, and the result is accumulated in slot 2 of
DP-RAM1. At the end of this procedure, the complete sumP ai· ˆsi is obtained. Subsequently, the error polynomial e0 is
written into DP-RAM1. This polynomial is also transformed to
the NTT domain, resulting in ˆe0, using the ping-pong approach
and temporarily using both DP-RAM1 and DP-RAM0. The
ﬁnal result is computed by adding ˆ e0 to the accumulated
product P ai· ˆsi, and the output P ai· ˆsi + ˆe0 is stored in
DP-RAM1, ready to be read by the encode unit.
This operation ﬂow highlights the need for an asymmetric
memory conﬁguration: DP-RAM1 must hold both the input
vector si and the output polynomial so they can be directly
accessed by the Encode Unit, which only reads from this
RAM. At the same time, the use of DP-RAM0 for intermediate
steps during the NTT computation ensures e ﬃcient ping-pong
memory switching, avoids memory conﬂicts, and supports
parallel execution of encoding, generation, and decoding oper-
ations.
B. Generation Unit
The generation unit, shown in Fig. 6, is responsible for
executing all the hashing and sampling operations in the
KEM-22 accelerator. It consists of two tightly coupled sub-
modules: the hashing core and the sampling core.
The hashing core implements the Keccak-based hashing
functions used in ML-KEM, including SHA3-256, SHA3-512,
SHAKE-128, and SHAKE-256. Due to the ﬁxed nature of
these operations, the Keccak architecture is highly optimized.
Referring to Fig. 6, the 1600-bit Keccak State register holds
both intermediate and ﬁnal values during hashing. The Keccak
Round Logic is a fully combinational circuit that performs a
complete round in a single clock cycle and updates the state
directly. Padding Logic is responsible for generating correctly
formatted 1600-bit inputs to the Keccak core, based on the
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 8

4722 IEEE INTERNET OF THINGS JOURNAL, VOL. 13, NO. 3, 1 FEBRUARY 2026
Fig. 6. Hardware architecture of the generation unit.
hash mode and operation stage. It accepts 512-bit blocks
from the seed register, along with additional data such as
nonces and matrix indices from the control unit. The seed
register itself is a 64-byte register that holds the expanded seed,
keeping it locally available for immediate sampling and min-
imizing Interface RAM access. Additionally, the seed register
serves as an I /O component, enabling 64-bit word-level data
exchange with the Interface RAM to simplify communication
and facilitate padding operations. The hashing core supports
noncontiguous processing of SHAKE input blocks, allowing
it to read data during idle cycles of the Interface RAM. This
feature enables ciphertext hashing during decapsulation to run
entirely in parallel with other operations.
The sampling core receives the 1344-bit Keccak output from
the hashing core and uses it to generate polynomial coeﬃcients
using one of three sampling algorithms: CBD with parameters
2 and 3 (referred to as CBD2 and CBD3, respectively) and
rejection sampling. The CBD method generates small centered
values by computing the di ﬀerence between the Hamming
weights (HWs) of two disjoint bit strings. In CBD2, each
coeﬃcient is computed using two pairs of bits, resulting in
a distribution over {−2,−1, 0, 1, 2 }. Similarly, CBD3 uses
three pairs of bits, yielding a slightly wider distribution. These
distributions are used to sample noise polynomials in the key
generation and encapsulation procedures. The third method is
rejection sampling, which is used in ML-KEM to generate
uniformly random coe ﬃcients modulo q. This method may
produce invalid values and therefore requires ﬁltering, which
can introduce variability in the number of input blocks needed
to generate a full polynomial. Each of the three algorithms has
distinct input byte requirements per cycle: CBD2 consumes 4
bytes, CBD3 uses 3 bytes, and rejection sampling requires 6
bytes. To e ﬃciently extract the needed bytes from the 1344-
bit input block, the sampling core includes a selection logic
block with four extraction patterns: one each for CBD2 and
rejection sampling and two for CBD3. CBD3 poses additional
Fig. 7. Hardware architecture of the encoding unit.
complexity, as it processes two consecutive 1344-bit blocks.
The ﬁnal byte of the ﬁrst block is preserved and concatenated
with the ﬁrst two bytes of the second block to form a valid 3-
byte input. In the second round of CBD3 processing, only the
ﬁrst 456 bits of the new block are used in conjunction with the
saved byte. This multistage extraction scheme, although more
complex than a simple multiplexer, signiﬁcantly improves byte
selection e ﬃciency and ensures compatibility with all three
sampling algorithms.
C. Encode and Decode Units
1) Encode Unit: The encoding function is used to serialize
and compress vectors of polynomials into byte arrays. These
operations are fundamental in key generation, encapsulation,
and decapsulation, where components such as public keys and
ciphertexts must be encoded e ﬃciently for communication
and hashing. The encoding process involves mapping each
coeﬃcient ai∈ Zq to an integer in [0 , 2d− 1], where d is a
variant-dependent bit-width. For example, ciphertext compo-
nents use d = 10 or d = 4, and certain intermediate values are
packed without compression, such as the concatenation of a
256-bit key and a 256-bit hash during shared secret derivation.
The hardware architecture of the encode unit is shown in
Fig. 7. It receives two couples of 12-bit input coe ﬃcients per
clock cycle and processes them through a double compressor,
enabling parallel processing for two encoding streams. The
output is routed through conﬁgurable encoders (labeled as Enc
128, Enc 160 , Enc 320 , and Enc 352 ), which support
diﬀerent target sizes depending on the ML-KEM parameter
set and protocol stage. A Poly_to_byte module provides
an alternate path for uncompressed serialization. Multiplexers
and control logic orchestrate the selection and packing of
data.
The design choice of processing two polynomial coe ﬃ-
cients per clock cycle—necessitating a double compression
unit within the encode unit—o ﬀers the best tradeo ﬀ for our
architecture. First, this input throughput is fully supported
by the memory interface of the polynomial unit without the
need for additional buﬀering or queuing mechanisms. Second,
the resulting data rate is su ﬃcient to sustain the bandwidth
requirements of all encoding functions integrated into the
encode unit, including both compressed and uncompressed
serialization paths. Finally, the output data rate, which reaches
a maximum of 24 bits per clock cycle, remains within the
capacity of the Interface RAM, again avoiding the need for
supplementary queues and contributing to an overall e ﬃcient
and low-latency datapath.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 9

MATTEO et al.: EFFICIENT POST-QUANTUM ML-KEM HARDW ARE ACCELERATOR ON 22-nm ASIC 4723
Fig. 8. Hardware architecture of the compressor.
Fig. 9. Hardware architecture of the decode unit.
The compression function, deﬁned as Compress q(x, d) =
⌊2d/q· x⌉ mod 2d, reduces the size of polynomial coe ﬃcients
by quantizing them from the original modulus q = 3329 to a
smaller range deﬁned by a target bit-width d. The hardware
architecture, reported in Fig. 8, is structured as a pipelined unit
capable of handling one coe ﬃcient per cycle. The input value
c, represented on 12 bits, is ﬁrst multiplied by 2d via a left shift
operation, followed by the addition of the rounding constant
q/2. The division by q is performed with the Barrett division,
which ﬁrst multiplies the input value by a precomputed ﬁxed-
point constant v = 226/q. The result is then right-shifted
by 26 bits, e ﬀectively approximating the division by q. This
yields the compressed output. To avoid quantization error, the
architecture includes a correction stage. The compressed result
is re-expanded by multiplying it with q and right shifting
by d. This reconstructed value is compared to the original
input; if it exceeds the original, a subtraction is performed to
decrement the compressed result by one. This postprocessing
correction guarantees that the ﬁnal output remains as close as
possible to the original value in terms of reconstruction. The
architecture is designed to support multiple compression types
dynamically through conﬁgurable shift parameters that control
the bit-width d. By avoiding true division and using only shift,
add, and multiply operations, the design achieves constant-
time behavior, low latency, and e ﬃcient resource utilization,
making it well suited for hardware-accelerated implementa-
tions of ML-KEM. The architecture of the compressor is
instead reported in Fig. 8.
2) Decode Unit: The decode unit, depicted in Fig. 9, is
responsible for deserializing and expanding the compressed
byte representation of polynomial coe ﬃcients, reconstructing
their original form for subsequent cryptographic processing
within ML-KEM. It processes four encoded polynomials at
a time, reading from the Interface RAM and storing the
decoded coe ﬃcients into the DP-RAM1 of the polynomial
unit. The decode unit mirrors the structure of the encode unit
and performs the inverse operations in three main phases:
decoding, expansion, and decompression. In the decoding
phase, the input byte stream is parsed based on the selected
mode—such as Dec 128 , Dec 160 , Dec 320 , and Dec
352 or the uncompressed from_msg and from_bytes
modes. Each mode deﬁnes how 1–6 incoming bytes are
interpreted to produce four intermediate coe ﬃcients, which
are typically represented on a reduced number of bits. These
intermediate values are then expanded with multiplication
by q. This multiplication ( Mul_q in both Figs. 8 and 9)
is e ﬃciently implemented via a shift-and-add architecture,
exploiting the constant nature of q. This design choice makes
the decode unit signiﬁcantly lighter than the encode unit,
allowing it to operate at a doubled rate. As a result, during
each clock cycle, the decode unit can receive up to 6 bytes
and output four expanded coe ﬃcients, either in a single cycle
or over two cycles, depending on the mode.
The ﬁnal stage applies a decompression or truncation proce-
dure speciﬁc to the decoding mode. This involves a right-shift
operation (and optional rounding), e ﬀectively inverting the
compression performed during encoding.
D. Interface RAM
The Interface RAM serves as the primary memory unit
of the accelerator, storing all input and output data required
for executing cryptographic operations. The Interface RAM is
sized 4.8 kB. To minimize complexity and overhead, mem-
ory regions are statically allocated to predeﬁned segments.
These segments are reused; once input data are consumed, its
memory region is repurposed for storing output, eliminating
the need for additional memory bu ﬀers. When the accelerator
is idle, the Interface RAM can be accessed directly by the
CPU through the external interface using 32- or 64-bit word
transactions. This direct access avoids any intermediary control
logic, simplifying communication and enabling e ﬃcient data
transfers—particularly when using a direct memory access
(DMA). Internally, diﬀerent modules of the accelerator exhibit
diverse memory access patterns. The generation unit performs
regular 64-bit aligned accesses, while the encode and decode
units access memory in variable widths ranging from 1 to 6
bytes per cycle. To support such irregular, ﬁne-grained access,
the Interface RAM exposes a byte-addressable interface and
allows selective byte writes on each transaction. This func-
tionality is implemented using a standard dual-port 32-bit
RAM with byte-enable support. A lightweight wrapper handles
address decoding, byte selection, and data alignment, provid-
ing a seamless view of a per-byte accessible memory space.
Since internal access patterns never exceed two simultaneous
words, the dual-port RAM architecture handles all concurrent
requests without contention. This design obviates the need
for additional FIFOs or temporary registers, thereby reducing
internal latency and saving area.
V. R ESULTS
The KEM-22 accelerator has been integrated into an ASIC
chip named V ASCO3 [20], taped out on a 22-nm FD-SOI
technology. The V ASCO3 chip incorporates multiple IP blocks
for cybersecurity applications, along with RISC-V proces-
sors. V ASCO3 is organized into multiple tiles, one of which
contains a system-on-chip (SoC) based on a 32-bit RISC-V
processor (CV32E40P), an open bus interface (OBI), a DMA,
and dedicated hardware accelerators for PQC algorithms,
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 10

4724 IEEE INTERNET OF THINGS JOURNAL, VOL. 13, NO. 3, 1 FEBRUARY 2026
Fig. 10. Floorplan of the V ASCO3 chip. In the red box, the KEM-22
accelerator.
TABLE III
AREA CONSUMPTION OF KEM-22
Fig. 11. Detail of the physical layout of the KEM-22 accelerator. The
submodules are highlighted with di ﬀerent colors.
including the KEM-22 accelerator. Fig. 10 shows the ﬂoorplan
of V ASCO3. The KEM-22 accelerator is highlighted by the red
box.
The maximum frequency of the KEM-22 accelerator is
938 MHz on the 22-nm FD-SOI technology, with an area of
0.0629 mm 2. The hierarchical area consumption in kGE is
reported in Table III.
As expected, the majority of the area is occupied by
the memories. The Interface RAM (4.8 kB) accounts for
approximately 114 kGE, while the polynomial unit, which
includes DP-RAM0 (2 kB) and DP-RAM1 (0.8 kB), occupies
around 126 kGE. All SRAM blocks are generated using
TABLE IV
EXECUTION TIME AND ENERGY OF ML-KEM F UNCTIONS @938 MH Z
the commercial memory compiler of the target library. It is
worth noting that the blue region in Fig. 11 represents only
the computational logic of the DKU and does not include
the corresponding memory macros. The ROM storing the
twiddle factors is implemented as combinational logic with
one output register (about 1.5 kGE, included in the polyno-
mial unit area), using a single 12-bit LUT shared by both
butterﬂy units (included in the DKU) and repeated for the
INTT.
Most of the remaining area is attributed to the generation
unit, which integrates both the hashing core and the sampling
core. The detailed ﬂoorplan of the KEM-22 accelerator is
illustrated in Fig. 11, visually showing the size ratio between
the diﬀerent submodules.
Table IV shows the performance of the KEM-22 accel-
erator. We measured the latency of the execution of the
KEM functions in ML-KEM at all three security levels.
Results are shown in both clock cycles and execution time
considering the maximum working frequency (i.e., 938 MHz).
To evaluate the power e ﬃciency of the proposed accelerator,
we performed a post-synthesis power analysis using the tool
PrimePower by Synopsys. The analysis was therefore con-
ducted on a back-annotated gate-level netlist obtained after
post-topological synthesis, including real parasitic informa-
tion. The power estimation was carried out at the typical
technological corner (TT), at 0.72 V and 125 ◦C. Under these
conditions, the accelerator exhibits an average dynamic power
consumption of 18.1 mW at 938 MHz, while at a reduced
operating frequency of 100 MHz, the power decreases to
2.98 mW. The corresponding energy per operation is reported
in Table IV.
To assess the eﬀectiveness of our proposed design, we com-
pared KEM-22 with the most recent ASIC implementations
of ML-KEM (or the previous version, CRYSTALS-Kyber), as
summarized in Table V. The comparison covers metrics such
as the technology node, maximum clock frequency, memory
usage, silicon area (in kGE), supported security levels, and
latency (in µs) for a full ML-KEM execution (i.e., KeyGen +
Encaps + Decaps).
We evaluate the eﬃciency of diﬀerent implementations with
the ATP, which provides a fair metric to compare the overall
eﬃciency of di ﬀerent designs by combining both latency and
area cost. In this analysis, the area is considered in gate
equivalents, which allows to perform a comparison that is
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 11

MATTEO et al.: EFFICIENT POST-QUANTUM ML-KEM HARDW ARE ACCELERATOR ON 22-nm ASIC 4725
TABLE V
COMPARISON WITH THE STATE OF THE ART
independent of the technology node. However, the execution
time is a ﬀected by the choice of the technology node since
the same design can work at higher frequency, thus showing
lower execution time, when implemented on a more advanced
technology.
To compare the overall e ﬃciency of di ﬀerent implementa-
tions, we adopted the normalized ATP metric, which jointly
captures latency and hardware cost . This metric provides a
balanced indicator of e ﬃciency, as it penalizes both large
area footprints and long execution times. The area of each
design is expressed in kGE to ensure technology-independent
comparison. However, the execution time is inherently aﬀected
by the underlying technology node since more advanced
processes can operate at higher frequencies. To mitigate this
eﬀect, we applied a technology-aware normalization using the
open-source DeepScaleTool [21], which rescales performance
metrics (such as frequency and delay) across di ﬀerent tech-
nologies based on realistic scaling models. Speciﬁcally, the
execution times of all reference designs were scaled to the
22-nm node used in our implementation. The normalized ATP
was then computed as follows:
ATPnorm = (Area × Scaled Execution Time )design
(Area × Execution Time)ours
. (3)
A normalized ATP of 1.00 therefore represents the e ﬃciency
level achieved by our accelerator, while values lower (higher)
than 1.00 indicate more (less) e ﬃcient designs compared to
ours.
The design from [9], despite its low area (253 kGE),
exhibits a higher ATP of 2.25 for Kyber-512 due to its limited
frequency. Bisheh-Niasar et al. [12] achieves a relatively low
ATP of 2.01 for Kyber-512 with just 222 kGE, but its ATP
increases to 2.99 at Kyber-768 due to additional dedicated
hardware for each parameter set, highlighting the ine ﬃciency
of nonscalable architectures. The KaLi processor from [13],
targeting both Kyber and Dilithium, achieves an ATP of
1.31 for Kyber-1024, leveraging a high 1-GHz frequency to
compensate for its high area of 747 kGE. Li et al. [10] show
a reasonable balance between speed and size with an ATP
of 1.81 for Kyber-512. On the other hand, Li et al. [11]
report the highest ATP among all evaluated works at 6.42,
due to its high area and limited clock frequency. Finally, the
designs in [14] and [15] do not report complete data (notably
the total area including memory), making it impossible to
derive meaningful ATP values for comparison. As reported
in Table V, our implementation achieves the lowest energy
per operation compared to the state of the art. This result
stems from both an e ﬃcient architectural design and the use
of 22-nm FD-SOI technology, whose reduced leakage and
improved dynamic power characteristics contribute to lower
overall power consumption. This analysis shows that while
many previous works achieve strong results for individual
Kyber or ML-KEM parameter sets, they often lack scalability
or su ﬀer from ine ﬃciencies when extended across multiple
security levels.
Our architecture achieves high performance and scalability
not through increased logic or memory, but through carefully
optimized resource sharing. Speciﬁcally, we avoid the use of
FIFO buﬀers and other intermediate storage structures, relying
solely on compact SRAM blocks for state and data handling.
Registers are employed only where necessary to achieve high
operating frequency, minimizing area overhead while meeting
timing constraints. Overall, the achieved frequency is con-
sistent with other state-of-the-art implementations in similar
technology nodes (e.g., 28-nm designs operating at 550 MHz
in [14] and 1 GHz in [13]), conﬁrming that the obtained results
in terms of ATP reﬂect an improvement in area consumption
while maintaining an operating frequency comparable to the
state of the art. This deliberate architectural choice enables
our design to support all ML-KEM parameter sets e ﬃciently,
without duplicating logic or inﬂating the footprint, o ﬀering
a practical and scalable solution for post-quantum ASIC
acceleration.
As the proposed architecture targets cryptographic work-
loads, it is essential to consider potential side-channel
vulnerabilities that may arise from physical implementations.
In this respect, the accelerator executes all arithmetic and
control operations in a constant-time manner, ensuring that its
latency is independent of the processed data and thus resilient
to timing-based attacks. Dedicated countermeasures against
power and electromagnetic analysis, such as masking or
hiding, are not yet implemented, as the current design focuses
on area and performance e ﬃciency. Lightweight protections
are planned for future work.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.


---

## Page 12

4726 IEEE INTERNET OF THINGS JOURNAL, VOL. 13, NO. 3, 1 FEBRUARY 2026
VI. C ONCLUSION
This article introduced a compact and scalable hardware
accelerator for the ML-KEM cryptosystem, implemented on a
22-nm ASIC technology. The architecture supports all three
security levels (ML-KEM-512, -768, and -1024) using a
uniﬁed design that avoids logic duplication and maintains
consistent e ﬃciency across modes. Furthermore, the design
avoids any use of FIFOs or intermediate bu ﬀering, relying
solely on SRAM memories for all temporary storage. Registers
are only used to increase pipeline stages and meet high-
frequency targets without increasing overall area. Compared
to state-of-the-art implementations, our design achieves the
lowest normalized ATP across all ML-KEM levels, with
the lowest power and energy per operation, demonstrating
superior hardware eﬃciency. This demonstrates the practicality
of our approach for post-quantum cryptographic accelerators
targeting resource-constrained and IoT systems.
REFERENCES
[1] C. Gidney and M. Ekerå, “How to factor 2048 bit RSA integers in
8 hours using 20 million noisy qubits,” Quantum, vol. 5, p. 433, Apr.
2021.
[2] P. W. Shor, “Algorithms for quantum computation: Discrete logarithms
and factoring,” in Proc. 35th Annu. Symp. F ound. Comput. Sci. , Nov.
1994, pp. 124–134.
[3] L. Chen, S. Jordan, Y .-K. Liu, D. Moody, and R. Peralta, Report on Post-
Quantum Cryptography , Standard NISTIR 8105, 2016, doi: 10.6028 /
NIST.IR.8105.
[4] Module-lattice-Based Key-Encapsulation Mechanism Standard, National
Institute of Standards and Technology, Gaithersburg, MD, USA, Aug.
13, 2024.
[5] Module-lattice-based Digital Signature Standard , Federal Information
Processing, Gaithersburg, MD, USA, Aug. 13, 2024.
[6] R. Avanzi et al., “CRYSTALS-kyber algorithm speciﬁcations and sup-
porting documentation,” Tech. Rep., 2021.
[7] D. Bellizia et al., “Post-quantum cryptography: Challenges and opportu-
nities for robust and secure HW design,” in Proc. IEEE Int. Symp. Defect
Fault Tolerance VLSI Nanotechnol. Syst. (DFT) , Oct. 2021, pp. 1–6.
[8] H. Nguyen, S. Huda, Y . Nogami, and T. T. Nguyen, “Security in post-
quantum era: A comprehensive survey on lattice-based algorithms,”
IEEE Access , vol. 13, pp. 89003–89024, 2025.
[9] A. Li et al., “A 273 µW 0.34 mm 2 eﬃcient CRYSTALS-KYBER
processor for PQC towards edge computing,” in Proc. IEEE Eur . Solid-
State Electron. Res. Conf. (ESSERC) , Sep. 2024, pp. 472–475.
[10] A. Li, J. Lu, D. Liu, and X. Li, “A 40nm 1.26 µ/Op energy-e ﬃcient
CRYSTALS-KYBER post-quantum crypto-processor with comprehen-
sive side channel security analysis and countermeasures,” in Proc. IEEE
Custom Integr . Circuits Conf. (CICC) , Apr. 2024, pp. 1–2.
[11] A. Li et al., “A 40nm 2.76 µj/op energy-e ﬃcient secure post-quantum
crypto-processor for crystals-kyber on module-lwe,” inProc. IEEE Asian
Solid-State Circuits Conf. (A-SSCC) , Nov. 2021, pp. 281–284.
[12] M. Bisheh-Niasar, R. Azarderakhsh, and M. Moza ﬀari-Kermani, “A
monolithic hardware implementation of kyber: Comparing apples to
apples in pqc candidates,” in Proc. 7th Int. Conf. Cryptol. Inf. Secur .
Latin Amer ., Oct. 2021, pp. 65–86, doi: 10.1007 /978-3-030-88238-9 6.
[13] A. Aikata, A. C. Mert, M. Imran, S. Pagliarini, and S. S. Roy, “KaLi:
A crystal for post-quantum security using kyber and dilithium,” IEEE
Trans. Circuits Syst. I, Reg. Papers , vol. 70, no. 2, pp. 747–758, Feb.
2023.
[14] Y . Zhao, R. Xie, G. Xin, and J. Han, “A high-performance domain-
speciﬁc processor with matrix extension of RISC-V for module-LWE
applications,” IEEE Trans. Circuits Syst. I, Reg. Papers , vol. 69, no. 7,
pp. 2871–2884, Jul. 2022.
[15] T.-H. Nguyen et al., “An area-time e ﬃcient hardware architecture for
ML-KEM post-quantum cryptography standard,” IEEE Access , vol. 13,
pp. 103834–103847, 2025.
[16] S. D. Matteo, I. Sarno, and S. Saponara, “CRYPHTOR: A memory-
uniﬁed NTT-based hardware accelerator for post-quantum CRYSTALS
algorithms,” IEEE Access , vol. 12, pp. 25501–25511, 2024.
[17] SHA-3 Standard: Permutation-based Hash and Extendable-output Func-
tions, National Institute of Standards and Technology, Gaithersburg, MD,
USA, 2015.
[18] P. Longa and M. Naehrig. (2016). Speeding Up the Number Theoretic
Transform for Faster Ideal Lattice-Based Cryptography . [Online]. Avail-
able: https://eprint.iacr.org/2016/504
[19] M. Imran et al., “Evaluating NTT /INTT implementation styles for post-
quantum cryptography,” IEEE Embedded Syst. Lett. , vol. 16, no. 4,
pp. 485–488, Dec. 2024.
[20] M. Carmona, S. Di Matteo, F. Lepin, M. Pezzin, E. Valea, and R. Wac-
quez, “V ASCO: ASIC test platform for hardware security research,” in
Proc. Design, Autom. Test Eur . Conf. , Mar. 2025. [Online]. Available:
https://cea.hal.science/cea-05026004/document
[21] S. Sarangi and B. Baas, “DeepScaleTool: A tool for the accurate
estimation of technology scaling in the deep-submicron era,” in Proc.
IEEE Int. Symp. Circuits Syst. (ISCAS) , May 2021, pp. 1–5.
Stefano Di Matteo received the M.Sc. and Ph.D.
degrees in electronic engineering and information
engineering from the University of Pisa, Pisa, Italy,
in 2019 and 2023, respectively.
He is currently a Tenure-Track Researcher in
hardware implementation of post-quantum cryptog-
raphy with CEA, Grenoble, France. His research
interests include hardware implementation of PQC
with countermeasures against physical attacks,
RISC-V architectures, and instruction-set extensions
for PQC.
Ivan Sarno received the bachelor’s degree in
computer science and the master’s degree in
cybersecurity from the University of Pisa, Pisa,
Italy, in 2019 and 2023, respectively. He is currently
pursuing the Ph.D. degree with CEA-List.
His research focuses on designing
and evaluating ISA extensions for
the RISC-V architecture to accelerate
post-quantum cryptography (PQC).
Emanuele Valea received the master’s degree in
electronic engineering from Politecnico di Torino,
Turin, Italy, in 2016, and the Ph.D. degree in
microelectronics from the University of Montpellier,
Montpellier, France, in 2020.
He is currently a Researcher with CEA, List,
Grenoble, France. His research interests include
hardware security and trust, cryptographic primitives
for microelectronics, and security-related aspects of
VLSI testing and reliability.
Sergio Saponara (Senior Member, IEEE) received
the Ph.D. degree in electronic engineering from the
University of Pisa, Pisa, Italy.
He was a Marie Curie Fellow at IMEC, Leuven,
Belgium. He is currently a Full Professor of electron-
ics with the University of Pisa. He has co-authored
about 300 scientiﬁc articles and holds 18 patents.
Dr. Saponara is a Founding Member of the IoT
CASS SiG. He has been a TPC Member of over
100 international IEEE and SPIE conferences. He is
an associate editor of several IEEE and IET journals.
Since 2017, he has been an IEEE IMS Distinguished Lecturer.
Authorized licensed use limited to: KUMOH NATIONAL INSTITUTE OF TECHNOLOGY. Downloaded on September 11,2026 at 14:55:16 UTC from IEEE Xplore.  Restrictions apply.

