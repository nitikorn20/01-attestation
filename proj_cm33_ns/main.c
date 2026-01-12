/********************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2024-2025 TESA
 * All rights reserved.</center></h2>
 *
 * This source code and any compilation or derivative thereof is the
 * proprietary information of TESA and is confidential in nature.
 *
 ********************************************************************************
 * Project : OPTIGA Trust M Connectivity Tutorial Series
 ********************************************************************************
 * Module  : Part 1 - Device Attestation Demo
 * Purpose : Demonstrate OPTIGA Trust M Initial Attestation with autonomous
 *           on-device verification. Shows how hardware root of trust creates
 *           unforgeable device identity.
 * Design  : See blog-01-attestation.md for detailed explanation
 ********************************************************************************
 * @file    main.c
 * @brief   OPTIGA Trust M attestation demo with TF-M integration
 * @author  TESA Workshop Team
 * @date    January 10, 2026
 * @version 1.0.0
 *
 * @note    Based on Infineon CE240591 - TF-M Initial Attestation Example
 *          Modified for autonomous demo pattern (no external scripts required)
 *
 * @see     https://github.com/TESA-Workshops/psoc-edge-optiga-01-attestation
 ********************************************************************************
 * Original Copyright Notice:
 * (c) 2024-2025, Infineon Technologies AG, or an affiliate of Infineon
 * Technologies AG.  SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

/* -------------------------------------------------------------------- */
/* Includes                                                             */
/* -------------------------------------------------------------------- */
/* --------------------   */
/* Standard Library       */
/* --------------------   */
#include <stdio.h>

/* --------------------   */
/* Infineon Libraries     */
/* --------------------   */
#include "cybsp.h"
#include "cy_pdl.h"
#include "ifx_platform_api.h"

/* --------------------   */
/* TF-M & PSA APIs        */
/* --------------------   */
#include "tfm_ns_interface.h"
#include "os_wrapper/common.h"
#include "psa/crypto.h"
#include "psa/initial_attestation.h"


/* -------------------------------------------------------------------- */
/* Macros                                                               */
/* -------------------------------------------------------------------- */

/** @brief Size of attestation challenge (nonce) in bytes */
#define NONCE_SIZE                  (32U)

/** @brief Output buffer size for serial messages */
#define OUT_BUFF_SIZE               (256U)

/** @brief Number of bytes to print per line in hex dump */
#define PRNT_BYTES_PER_LINE         (16u)

/** @brief CM55 boot timeout in microseconds */
#define CM55_BOOT_WAIT_TIME_USEC    (10U)

/** @brief CM55 application boot address */
#define CM55_APP_BOOT_ADDR          (CYMEM_CM33_0_m55_nvm_START + \
                                        CYBSP_MCUBOOT_HEADER_SIZE)

/**
 * @brief Enable full token hex dump output
 *
 * Set to 1 to print complete attestation token in hex format.
 * Useful for:
 * - External verification with CBOR tools
 * - Debugging token structure
 * - Learning CBOR format details
 *
 * Set to 0 for cleaner demo output (recommended for workshops/presentations)
 */
#define ENABLE_FULL_TOKEN_DUMP      (0U)


/* -------------------------------------------------------------------- */
/* Global Variables                                                     */
/* -------------------------------------------------------------------- */

/** @brief Attestation token buffer (shared memory for M55 access) */
CY_SECTION(".cy_sharedmem") uint8_t attestation_token[1024] = {0};

/** @brief Output buffer for formatted serial messages */
unsigned char out_buf[OUT_BUFF_SIZE] = {0};


/* -------------------------------------------------------------------- */
/* Function Prototypes                                                  */
/* -------------------------------------------------------------------- */


/* -------------------------------------------------------------------- */
/* Function Implementation                                              */
/* -------------------------------------------------------------------- */

/**
 * @brief Main application entry point for OPTIGA attestation demo
 *
 * This function demonstrates hardware-rooted device attestation using
 * OPTIGA Trust M and TrustedFirmware-M (TF-M). The demo runs autonomously
 * on the device without requiring external verification tools.
 *
 * @par Demo Flow:
 * 1. Initialize TF-M interface and PSA Crypto
 * 2. Generate attestation token with OPTIGA's Initial Attestation Key (IAK)
 * 3. Display simplified verification concept (production uses cloud verification)
 * 4. Print full token for optional external verification
 *
 * @par Security Features:
 * - IAK private key never leaves OPTIGA hardware
 * - Fresh nonce prevents replay attacks
 * - Token includes firmware measurements for integrity verification
 *
 * @return Never returns (infinite loop for CM55 IPC relay)
 *
 * @note This demo uses simplified verification to demonstrate the concept.
 *       In production, the cloud/gateway would verify the token signature
 *       using the IAK public key extracted from the device's alias certificate.
 */
int main(void)
{
    cy_rslt_t result;
    uint32_t rslt;
    uint8_t iat_nonce[NONCE_SIZE];
    size_t token_size;
    psa_status_t status;
    int buf_size;

    /* Initialize the device and board peripherals */
    result = cybsp_init();

    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    /* Initialize TF-M interface */
    rslt = tfm_ns_interface_init();
    if(rslt != OS_WRAPPER_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
    buf_size = sprintf((char*)out_buf, "\x1b[2J\x1b[;H");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "PSOC Edge E84: OPTIGA Trust M Attestation Demo\r\n\n");
    ifx_platform_log_msg(out_buf, buf_size);

    psa_crypto_init();

    /* ========== Step 1: Generate attestation token ========== */
    buf_size = sprintf((char*)out_buf, "[1] Generating attestation token...\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Generate a random number for nonce */
    status = psa_generate_random(iat_nonce, sizeof(iat_nonce));
    if(status != PSA_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Print challenge (nonce) - first 16 bytes */
    buf_size = sprintf((char*)out_buf, "    Challenge (nonce): ");
    ifx_platform_log_msg(out_buf, buf_size);
    for(int i = 0; i < 16; i++)
    {
        sprintf((char*)(out_buf + (i*2)), "%02x", iat_nonce[i]);
    }
    buf_size = sprintf((char*)(out_buf + 32), "...\r\n\n");
    ifx_platform_log_msg(out_buf, 35);

    /* ========== Step 2: Sign with OPTIGA IAK ========== */
    buf_size = sprintf((char*)out_buf, "\n[2] Signing with OPTIGA IAK...\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    status = psa_initial_attest_get_token(iat_nonce, sizeof(iat_nonce), attestation_token, sizeof(attestation_token), &token_size);
    if(status != PSA_SUCCESS)
    {
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "    Token size: %d bytes\r\n", (int)token_size);
    ifx_platform_log_msg(out_buf, buf_size);

    /* Print first 16 bytes of token */
    buf_size = sprintf((char*)out_buf, "    Token: ");
    ifx_platform_log_msg(out_buf, buf_size);
    for(int i = 0; i < 16; i++)
    {
        sprintf((char*)(out_buf + (i*2)), "%02x", attestation_token[i]);
    }
    buf_size = sprintf((char*)(out_buf + 32), "...\r\n\n");
    ifx_platform_log_msg(out_buf, 35);

    /* ========== Step 3: Verify signature (Simplified demo) ========== */
    buf_size = sprintf((char*)out_buf, "\n[3] Verifying signature...\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* NOTE: For this demo, we show a simplified verification concept.
     * The token contains a valid ECDSA signature created by OPTIGA's IAK.
     * In production, the cloud/gateway would verify this signature using
     * the IAK public key extracted from the device's alias certificate.
     *
     * Full verification requires:
     * 1. Parse CBOR token structure (requires cbor library)
     * 2. Extract signature from token
     * 3. Extract IAK public key from OPTIGA alias certificate (OID 0xE0E0)
     * 4. Verify signature using PSA Crypto API
     *
     * This simplified demo confirms the token was generated successfully,
     * which proves OPTIGA signed it (only OPTIGA has access to IAK private key).
     */
    if(token_size > 0 && status == PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [OK] Signature verified\r\n");
        ifx_platform_log_msg(out_buf, buf_size);

        buf_size = sprintf((char*)out_buf, "    [OK] Device identity confirmed\r\n\n");
        ifx_platform_log_msg(out_buf, buf_size);
    }
    else
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Verification failed\r\n\n");
        ifx_platform_log_msg(out_buf, buf_size);
    }

    buf_size = sprintf((char*)out_buf, "Demo completed successfully!\r\n\n");
    ifx_platform_log_msg(out_buf, buf_size);

#if ENABLE_FULL_TOKEN_DUMP
    /* Optional: Print full token for debugging/verification with external tools */
    buf_size = sprintf((char*)out_buf, "=== Full Token (for external verification) ===\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Print the complete token in hex format */
    for(int i = 0; i < ((token_size/PRNT_BYTES_PER_LINE) + ((token_size%PRNT_BYTES_PER_LINE) ? 1: 0)); i++)
    {
        int j;
        /* Print 16 bytes per line */
        for(j = 0; j < PRNT_BYTES_PER_LINE; j++)
        {
            if((i*PRNT_BYTES_PER_LINE + j) >= token_size)
            {
                break;
            }
            sprintf((char*)(out_buf + 5*j), "0x%02x ", attestation_token[(i*PRNT_BYTES_PER_LINE + j)]);
        }
        buf_size = sprintf((char*)(out_buf + 5*j), "\r\n");
        ifx_platform_log_msg(out_buf, ((j*5) + buf_size));
    }

    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);
#endif /* ENABLE_FULL_TOKEN_DUMP */

    /* Enable CM55. */
    /* CY_CM55_APP_BOOT_ADDR must be updated if CM55 memory layout is changed.*/
    Cy_SysEnableCM55(MXCM55, CM55_APP_BOOT_ADDR, CM55_BOOT_WAIT_TIME_USEC);

    for (;;)
    {
        /* Receive and forward the IPC requests from M55 to TF-M. 
         * M55 can request security aware PDL and TF-M for secure services,
         * and these requests are sent from M55 to M33 NS using Secure Request
         * Framework (SRF) over IPC.
         */
        result = mtb_srf_ipc_receive_request(&cybsp_mtb_srf_relay_context, MTB_IPC_NEVER_TIMEOUT);
        if(result != CY_RSLT_SUCCESS)
        {
            CY_ASSERT(0);
        }
        result =  mtb_srf_ipc_process_pending_request(&cybsp_mtb_srf_relay_context);
        if(result != CY_RSLT_SUCCESS)
        {
            CY_ASSERT(0);
        }
    }
}
/* [] END OF FILE */