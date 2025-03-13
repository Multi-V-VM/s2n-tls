/*
 * The WebAssembly Live Migration Project
 *
 * Copyright 2024 Regents of the Univeristy of California
 * UC Santa Cruz Sluglab.
 */

#include "tls/extensions/s2n_attestation.h"

#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

/* Set the attestation type for the connection */
S2N_RESULT s2n_connection_set_attestation_type(struct s2n_connection *conn, s2n_attestation_type type)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE(type > S2N_ATTESTATION_NONE && type < S2N_ATTESTATION_MAX, S2N_ERR_INVALID_ATTESTATION_TYPE);

    /* Allocate attestation context if not already done */
    if (!conn->attestation_context) {
        struct s2n_blob attestation_context = { 0 };
        RESULT_GUARD_POSIX(s2n_alloc(&attestation_context, sizeof(struct s2n_attestation_context)));
        conn->attestation_context = (struct s2n_attestation_context *) (void *) attestation_context.data;
        RESULT_ENSURE_REF(conn->attestation_context);
        memset(conn->attestation_context, 0, sizeof(struct s2n_attestation_context));
    }

    conn->attestation_context->attestation_requested = 1;
    conn->attestation_context->attestation_type = type;
    conn->attestation_context->attestation_type_set = 1;

    return S2N_RESULT_OK;
}

/* Get the attestation type for the connection */
S2N_RESULT s2n_connection_get_attestation_type(struct s2n_connection *conn, s2n_attestation_type *type)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(type);
    RESULT_ENSURE_REF(conn->attestation_context);
    RESULT_ENSURE(conn->attestation_context->attestation_type_set, S2N_ERR_ATTESTATION_EVIDENCE_MISSING);

    *type = conn->attestation_context->attestation_type;

    return S2N_RESULT_OK;
}

/* Set the attestation evidence for the connection */
S2N_RESULT s2n_connection_set_attestation_evidence(struct s2n_connection *conn, const uint8_t *evidence, uint32_t size)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(evidence);
    RESULT_ENSURE(size > 0, S2N_ERR_ATTESTATION_EVIDENCE_MISSING);

    /* Attestation type must be set first */
    RESULT_ENSURE(conn->attestation_context && conn->attestation_context->attestation_type_set,
            S2N_ERR_INVALID_ATTESTATION_TYPE);

    struct s2n_blob evidence_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&evidence_blob, size));
    memcpy(evidence_blob.data, evidence, size);
    evidence_blob.size = size;

    /* Free existing evidence if any */
    if (conn->attestation_context->local_evidence.evidence.data) {
        RESULT_GUARD_POSIX(s2n_free(&conn->attestation_context->local_evidence.evidence));
    }

    conn->attestation_context->local_evidence.evidence = evidence_blob;
    conn->attestation_context->local_evidence.type = conn->attestation_context->attestation_type;

    return S2N_RESULT_OK;
}

/* Get the peer's attestation evidence */
S2N_RESULT s2n_connection_get_peer_attestation_evidence(struct s2n_connection *conn, uint8_t **evidence, uint32_t *size)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(evidence);
    RESULT_ENSURE_REF(size);
    RESULT_ENSURE_REF(conn->attestation_context);

    RESULT_ENSURE(conn->attestation_context->peer_evidence.evidence.data, S2N_ERR_ATTESTATION_EVIDENCE_MISSING);
    RESULT_ENSURE(conn->attestation_context->peer_evidence.evidence.size > 0, S2N_ERR_ATTESTATION_EVIDENCE_MISSING);

    *evidence = conn->attestation_context->peer_evidence.evidence.data;
    *size = conn->attestation_context->peer_evidence.evidence.size;

    return S2N_RESULT_OK;
}

/* Verify attestation evidence - placeholder for actual verification logic */
S2N_RESULT s2n_connection_verify_attestation_evidence(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->attestation_context);

    RESULT_ENSURE(conn->attestation_context->peer_evidence.evidence.data, S2N_ERR_ATTESTATION_EVIDENCE_MISSING);
    RESULT_ENSURE(conn->attestation_context->peer_evidence.evidence.size > 0, S2N_ERR_ATTESTATION_EVIDENCE_MISSING);

    /* 
     * TODO: Implement actual attestation evidence verification logic
     * This would involve:
     * 1. Parse the attestation evidence based on type
     * 2. Verify signature on evidence
     * 3. Check attestation extension values
     * 4. Validate measurements against reference values
     * 5. Ensure challenge matches what was sent
     */

    return S2N_RESULT_OK;
}

/* Generate attestation evidence - placeholder for actual generation logic */
S2N_RESULT s2n_connection_generate_attestation_evidence(struct s2n_connection *conn, const uint8_t *challenge, uint32_t challenge_size)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(challenge);
    RESULT_ENSURE(challenge_size > 0, S2N_ERR_INVALID_ARGUMENT);
    RESULT_ENSURE_REF(conn->attestation_context);
    RESULT_ENSURE(conn->attestation_context->attestation_type_set, S2N_ERR_INVALID_ATTESTATION_TYPE);

    /* 
     * TODO: Implement actual attestation evidence generation logic
     * This would involve:
     * 1. Call into appropriate attestation mechanism (SGX, TZ, etc.)
     * 2. Include the challenge in the attestation
     * 3. Format the evidence according to expected format
     */

    /* The following is a dummy implementation for placeholder purposes */
    struct s2n_blob evidence_blob = { 0 };
    /* Just using challenge as evidence for now, real implementation would generate proper evidence */
    RESULT_GUARD_POSIX(s2n_alloc(&evidence_blob, challenge_size + 4));

    /* Add a simple header to distinguish this as generated evidence */
    evidence_blob.data[0] = 'A';
    evidence_blob.data[1] = 'T';
    evidence_blob.data[2] = 'T';
    evidence_blob.data[3] = conn->attestation_context->attestation_type;

    /* Copy challenge data */
    memcpy(evidence_blob.data + 4, challenge, challenge_size);
    evidence_blob.size = challenge_size + 4;

    /* Free existing evidence if any */
    if (conn->attestation_context->local_evidence.evidence.data) {
        RESULT_GUARD_POSIX(s2n_free(&conn->attestation_context->local_evidence.evidence));
    }

    conn->attestation_context->local_evidence.evidence = evidence_blob;
    conn->attestation_context->local_evidence.type = conn->attestation_context->attestation_type;

    /* Store the challenge for verification */
    if (conn->attestation_context->local_evidence.challenge.data) {
        RESULT_GUARD_POSIX(s2n_free(&conn->attestation_context->local_evidence.challenge));
    }

    struct s2n_blob challenge_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&challenge_blob, challenge_size));
    memcpy(challenge_blob.data, challenge, challenge_size);
    challenge_blob.size = challenge_size;

    conn->attestation_context->local_evidence.challenge = challenge_blob;

    return S2N_RESULT_OK;
}