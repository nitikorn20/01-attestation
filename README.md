# Part 1: Device Identity with Attestation

**Prove your device is genuine - Unforgeable hardware-rooted identity**

> **Part 1 of 3** | [← Back to Tutorial Hub](https://github.com/nitikorn20/optiga-tfm-connectivity-tutorials) | [Part 2: Signing →](https://github.com/nitikorn20/psoc-edge-optiga-02-signing)

[![Difficulty](https://img.shields.io/badge/Difficulty-Beginner-green)]()
[![Time](https://img.shields.io/badge/Time-30_minutes-blue)]()
[![Platform](https://img.shields.io/badge/Platform-PSoC™_Edge_E84-blue)]()

---

## What You'll Build

A self-contained attestation demo that:
- ✅ Generates cryptographic attestation tokens
- ✅ Uses OPTIGA's Initial Attestation Key (IAK)
- ✅ Proves hardware-rooted device identity

**Time:** 30 minutes | **Level:** Beginner

**Why attestation matters:** Proves your device is genuine and firmware hasn't been tampered. See [Why Hardware Security Matters](https://github.com/nitikorn20/optiga-tfm-connectivity-tutorials#why-hardware-security-matters) in the Tutorial Hub for attack scenarios and security comparison.

---

## How It Works

<div align="center">

![Attestation Process Diagram](images/attestation-flow-3steps.png)

</div>

**OPTIGA's Role:**
- IAK (Initial Attestation Key) never leaves hardware
- Signing happens inside OPTIGA chip
- Each device has unique IAK

---

## Quick Start (5 Minutes)

### Prerequisites

**Hardware:**
- [PSoC™ Edge E84 Evaluation Kit (KIT_PSE84_EVAL_EPC2)](https://www.infineon.com/cms/en/product/evaluation-boards/kit-pse84-eval-epc2/)
  - Includes integrated **OPTIGA™ Trust M** chip (pre-configured)
- USB Type-C cable

**Software:**
- [ModusToolbox™ 3.6+](https://www.infineon.com/modustoolbox)
- Serial terminal (115200 baud, 8N1)

**Jumper Settings:**
- BOOT SW: **OFF**
- J20, J21: **NC** (not connected)

See [Hardware Setup Guide](https://github.com/nitikorn20/optiga-tfm-connectivity-tutorials#prerequisites) in Tutorial Hub for photos.

---

### Build and Run

```bash
# 1. Clone this repository
git clone https://github.com/nitikorn20/psoc-edge-optiga-01-attestation
cd psoc-edge-optiga-01-attestation

# 2. Build all projects
make -j8

# 3. Flash to device
make program

# 4. Open serial terminal (115200 baud, 8N1)
```

---

## Expected Output

```
PSOC Edge E84: OPTIGA Trust M Attestation Demo

[1] Generating attestation token...
    Challenge (nonce): d5913b51486dba7637eb0143d30faf2c...

[2] Signing with OPTIGA IAK...
    Token size: 559 bytes
    Token: d28443a10126a05901e3a80a5820d591...

[3] Verifying signature...
    [OK] Signature verified
    [OK] Device identity confirmed

Demo completed successfully!
```

### What Just Happened?

1. **TF-M collected boot measurements** (firmware hashes measured by bootloader)
2. **OPTIGA signed token** with IAK private key (never exposed to MCU)
3. **Token ready for cloud verification** (cryptographically valid)

🎉 **Success!** Device now has hardware-rooted identity that cannot be cloned.

---

## Understanding Attestation

### Token Contents (CBOR Format)

The attestation token contains:

```json
{
  "psa-instance-id": "01...",      // Unique device ID
  "psa-nonce": "d591...",           // Challenge for freshness
  "psa-software-components": [     // Boot measurements
    {"measurement-type": "BL2", "measurement-value": "hash..."},
    {"measurement-type": "S",   "measurement-value": "hash..."},
    {"measurement-type": "NS",  "measurement-value": "hash..."}
  ],
  // ... additional claims ...
  // + ECDSA signature (signed by OPTIGA IAK)
}
```

**Key Security Properties:**
- **Freshness:** Nonce prevents replay attacks
- **Integrity:** Firmware hashes prove no tampering
- **Authenticity:** Signature proves genuine OPTIGA device

**Learn more:** [PSA Initial Attestation API Spec](https://arm-software.github.io/psa-api/attestation/1.0/)

---

### Demo vs Production

| Aspect               | This Demo         | Production Deployment        |
| -------------------- | ----------------- | ---------------------------- |
| **Challenge source** | Device generates  | **Cloud sends unique nonce** |
| **Verification**     | Demo message only | **Cloud verifies signature** |
| **Public key**       | Not extracted     | **From device certificate**  |
| **Decision**         | Educational       | **Accept/reject device**     |

**Production Flow:**


<div align="center">

![Sequence diagram showing Cloud ↔ Device ↔ OPTIGA interaction](images/production-attestation-flow.png)

</div>

**For production implementation:** See [Infineon's TF-M Attestation Example](https://github.com/Infineon/mtb-example-psoc-edge-epc2-tfm-attestation) for full cloud verification setup.

---

## Key Code Sections

### Step 1: Generate Challenge

```c
uint8_t iat_nonce[32];
psa_generate_random(iat_nonce, sizeof(iat_nonce));
```

**Purpose:** Proves token is fresh (not replayed)

---

### Step 2: Request Attestation Token

```c
psa_initial_attest_get_token(
    iat_nonce, sizeof(iat_nonce),                      // Challenge
    attestation_token, sizeof(attestation_token),      // Output buffer
    &token_size                                        // Token size
);
```

**What happens internally:**
1. TF-M collects boot measurements
2. TF-M packages claims into CBOR format
3. **TF-M → OPTIGA:** Sign with IAK (via I²C)
4. **OPTIGA:** Sign internally, return signature
5. Token assembled and returned

**Critical security point:** IAK private key **never leaves OPTIGA** chip.

---

## Project Structure

```
psoc-edge-optiga-01-attestation/
├── proj_bootloader/       # Edge Protect Bootloader (measures firmware)
├── proj_cm33_s/           # TF-M (Secure firmware with attestation service)
├── proj_cm33_ns/          # Application (Non-Secure)
│   └── main.c             # ← Attestation demo code
├── proj_cm55/             # CM55 core
└── Makefile               # Build configuration
```

**Main code:** [proj_cm33_ns/main.c](proj_cm33_ns/main.c)

---

## Advanced: External Verification

Want to verify tokens externally (like cloud would)?

### Option 1: Use TF-M Verification Tools

1. Enable full token dump in `main.c`:
   ```c
   #define ENABLE_FULL_TOKEN_DUMP  (1U)
   ```

2. Extract token and IAK public key:
   ```bash
   cd scripts
   ./extract_iat_iak_pkey.sh
   ```

3. Verify with TF-M tools:
   ```bash
   git clone https://github.com/TrustedFirmware-M/tf-m-tools
   cd tf-m-tools/iat-verifier
   pip install -r requirements.txt
   python scripts/check_iat -t PSA-2.0.0-token \
     -k IAK_PUB_KEY.pem Attestation_token.cbor
   ```

**Expected output:**
```
Signature: OK
Token format: PSA-2.0.0-token
```

**Detailed guide:** [Infineon TF-M Attestation README](https://github.com/Infineon/mtb-example-psoc-edge-epc2-tfm-attestation#verifying-the-attestation-token)

---

### Option 2: Continue to Part 2

📘 **[Part 2: Digital Signatures](https://github.com/nitikorn20/psoc-edge-optiga-02-signing)**

Learn complete sign/verify cycle with OPTIGA device keys.

---

## Troubleshooting

<details>
<summary><strong>Device doesn't boot or no serial output</strong></summary>

**Check jumper settings:**
- BOOT SW: Must be in **OFF** position
- J20, J21: **Not connected** (tristate)

</details>

<details>
<summary><strong>Token size is 0 or PSA error</strong></summary>

**Possible causes:**
1. TF-M boot failed - Check bootloader logs
2. OPTIGA I²C error - Verify chip is soldered correctly
3. RNG not initialized - Ensure `psa_crypto_init()` succeeds

</details>

<details>
<summary><strong>Build fails: "psa/initial_attestation.h not found"</strong></summary>

**Solution:**
```bash
make getlibs  # Ensure TF-M library is downloaded
```

</details>

**More help:** See [Infineon Community Forums](https://community.infineon.com/)

---

## What's Different from Infineon Example?

This tutorial is based on **Infineon CE240591** with these enhancements:

✅ **Autonomous demo** - No Python scripts required
✅ **Step-by-step output** - Clear `[1] [2] [3]` progress
✅ **Verification concept** - Shows what production would do
✅ **Educational focus** - Explains OPTIGA's role clearly

**Original Infineon example:** [mtb-example-psoc-edge-epc2-tfm-attestation](https://github.com/Infineon/mtb-example-psoc-edge-epc2-tfm-attestation)

**Detailed changes:** See [CODE_CHANGES.md](CODE_CHANGES.md)

---

## Learn More

### Next Tutorial
📚 **[Part 2: Digital Signatures](https://github.com/nitikorn20/psoc-edge-optiga-02-signing)** - ECDSA signing with hardware-protected keys

### Documentation

**Official Resources:**
- [OPTIGA™ Trust M GitHub](https://github.com/Infineon/optiga-trust-m) - SDK and examples
- [OPTIGA™ Trust M Product Page](https://www.infineon.com/optiga-trust-m) - Datasheets
- [PSoC™ Edge E84 Docs](https://www.infineon.com/psoc-edge) - MCU documentation
- [PSA Attestation API](https://arm-software.github.io/psa-api/attestation/1.0/) - Standard specification
- [TF-M User Guide](https://tf-m-user-guide.trustedfirmware.org/) - TrustedFirmware-M docs

**Community:**
- [Infineon Developer Community](https://community.infineon.com/) - Forums
- [ModusToolbox Forums](https://community.infineon.com/t5/ModusToolbox/bd-p/ModusToolbox) - Build help

---

## Next Steps

**✅ Completed Part 1!** You now understand hardware-rooted device identity.

**Continue learning:**
- [**Part 2: Digital Signatures →**](https://github.com/nitikorn20/psoc-edge-optiga-02-signing) - Sign data with OPTIGA keys (45 min)
- [**Part 3: Secure Channel →**](https://github.com/nitikorn20/psoc-edge-optiga-03-secure-channel) - End-to-end encryption (90 min)

**Explore more:**
- [**Tutorial Series Hub**](https://github.com/nitikorn20/optiga-tfm-connectivity-tutorials)
- [**Why OPTIGA is Essential**](https://github.com/nitikorn20/optiga-tfm-connectivity-tutorials/blob/main/docs/why-optiga-trust-m.md) - Deep dive article

---

## License

This example is based on Infineon's CE240591.

**Original Code:** Copyright (c) 2024-2025, Infineon Technologies AG
**Tutorial Modifications:** Copyright (c) 2024-2025, TESA

Licensed under Apache 2.0. See [LICENSE](LICENSE) file.

---

## Contributing

Found a bug or have suggestions?

- **Report Issues:** [Tutorial Repository Issues](https://github.com/nitikorn20/optiga-tfm-connectivity-tutorials/issues)
- **Original Example:** [Infineon CE240591 Issues](https://github.com/Infineon/mtb-example-psoc-edge-epc2-tfm-attestation/issues)

---

<div align="center">

**🔒 Hardware-rooted device identity that cannot be cloned**

**[Tutorial Series →](https://github.com/nitikorn20/optiga-tfm-connectivity-tutorials)** | **[Next: Digital Signatures →](https://github.com/nitikorn20/psoc-edge-optiga-02-signing)**

</div>
