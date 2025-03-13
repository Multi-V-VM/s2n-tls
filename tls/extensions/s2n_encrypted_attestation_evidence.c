/*
 * The WebAssembly Live Migration Project
 *
 * Copyright 2024 Regents of the Univeristy of California
 * UC Santa Cruz Sluglab.
 */

#include "crypto/s2n_hash.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_attestation.h"
#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

/* Should send the attestation evidence in encrypted extensions */
static bool s2n_encrypted_attestation_evidence_should_send(struct s2n_connection *conn)
{
    return conn && conn->mode == S2N_SERVER && conn->attestation_context
            && conn->attestation_context->attestation_requested
            && conn->attestation_context->local_evidence.evidence.size > 0;
}

/* Generate a challenge using the handshake hash for binding to the connection */
static int s2n_generate_challenge_from_handshake(struct s2n_connection *conn, struct s2n_blob *challenge)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(challenge);

    /* Use the handshake hash as the challenge binding to the connection */
    struct s2n_hash_state hash_state;
    uint8_t hash_digest[S2N_MAX_DIGEST_LEN];

    s2n_hash_algorithm hash_alg;
    POSIX_GUARD(s2n_hmac_hash_alg(conn->secure->cipher_suite->prf_alg, &hash_alg));
    uint8_t hash_size = 0;

    POSIX_GUARD(s2n_hash_digest_size(hash_alg, &hash_size));
    POSIX_ENSURE(hash_size <= sizeof(hash_digest), S2N_ERR_HASH_DIGEST_FAILED);

    POSIX_GUARD(s2n_hash_new(&hash_state));
    POSIX_GUARD(s2n_hash_copy(&hash_state, &conn->handshake.hashes->hash_workspace));
    POSIX_GUARD(s2n_hash_digest(&hash_state, hash_digest, hash_size));
    POSIX_GUARD(s2n_hash_free(&hash_state));

    /* Allocate the challenge blob if needed */
    if (challenge->data == NULL) {
        POSIX_GUARD(s2n_alloc(challenge, hash_size));
    } else {
        POSIX_ENSURE(challenge->size >= hash_size, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    }

    memcpy(challenge->data, hash_digest, hash_size);
    challenge->size = hash_size;

    return S2N_SUCCESS;
}

/* Send the attestation evidence in encrypted extensions */
int s2n_encrypted_attestation_evidence_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(conn->attestation_context);

    /* Generate the challenge for this connection */
    struct s2n_blob challenge = { 0 };
    POSIX_GUARD(s2n_generate_challenge_from_handshake(conn, &challenge));

    /* Store the challenge in local evidence for verification */
    if (conn->attestation_context->local_evidence.challenge.data == NULL) {
        POSIX_GUARD(s2n_dup(&challenge, &conn->attestation_context->local_evidence.challenge));
    }

    /* Write the attestation type */
    POSIX_GUARD(s2n_stuffer_write_uint16(out, conn->attestation_context->attestation_type));

    /* Write the evidence size and data */
    POSIX_GUARD(s2n_stuffer_write_uint32(out, conn->attestation_context->local_evidence.evidence.size));
    POSIX_GUARD(s2n_stuffer_write_bytes(out, conn->attestation_context->local_evidence.evidence.data,
            conn->attestation_context->local_evidence.evidence.size));

    /* Write the challenge size and data */
    POSIX_GUARD(s2n_stuffer_write_uint32(out, challenge.size));
    POSIX_GUARD(s2n_stuffer_write_bytes(out, challenge.data, challenge.size));

    return S2N_SUCCESS;
}

/* Process the attestation evidence from encrypted extensions */
int s2n_encrypted_attestation_evidence_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(extension);
    POSIX_ENSURE_REF(conn->attestation_context);

    /* Read the attestation type */
    uint16_t attestation_type;
    POSIX_GUARD(s2n_stuffer_read_uint16(extension, &attestation_type));

    /* Validate the attestation type matches what was requested */
    POSIX_ENSURE(attestation_type == conn->attestation_context->attestation_type,
            S2N_ERR_INVALID_ATTESTATION_TYPE);

    /* Read the evidence */
    uint32_t evidence_size;
    POSIX_GUARD(s2n_stuffer_read_uint32(extension, &evidence_size));

    /* Allocate space for the evidence if needed */
    if (conn->attestation_context->peer_evidence.evidence.data == NULL) {
        POSIX_GUARD(s2n_alloc(&conn->attestation_context->peer_evidence.evidence, evidence_size));
    } else {
        POSIX_ENSURE(conn->attestation_context->peer_evidence.evidence.size >= evidence_size,
                S2N_ERR_INSUFFICIENT_MEM_SIZE);
    }

    POSIX_GUARD(s2n_stuffer_read_bytes(extension, conn->attestation_context->peer_evidence.evidence.data, evidence_size));
    conn->attestation_context->peer_evidence.evidence.size = evidence_size;
    conn->attestation_context->peer_evidence.type = attestation_type;

    /* Read the challenge */
    uint32_t challenge_size;
    POSIX_GUARD(s2n_stuffer_read_uint32(extension, &challenge_size));

    /* Allocate space for the challenge if needed */
    if (conn->attestation_context->peer_evidence.challenge.data == NULL) {
        POSIX_GUARD(s2n_alloc(&conn->attestation_context->peer_evidence.challenge, challenge_size));
    } else {
        POSIX_ENSURE(conn->attestation_context->peer_evidence.challenge.size >= challenge_size,
                S2N_ERR_INSUFFICIENT_MEM_SIZE);
    }

    POSIX_GUARD(s2n_stuffer_read_bytes(extension, conn->attestation_context->peer_evidence.challenge.data, challenge_size));
    conn->attestation_context->peer_evidence.challenge.size = challenge_size;

    /* Verify the challenge relates to this handshake */
    struct s2n_blob local_challenge = { 0 };
    POSIX_GUARD(s2n_generate_challenge_from_handshake(conn, &local_challenge));

    POSIX_ENSURE(local_challenge.size == challenge_size, S2N_ERR_ATTESTATION_CHALLENGE_MISMATCH);
    POSIX_ENSURE(memcmp(local_challenge.data, conn->attestation_context->peer_evidence.challenge.data,
                         challenge_size)
                    == 0,
            S2N_ERR_ATTESTATION_CHALLENGE_MISMATCH);

    s2n_free(&local_challenge);

    return S2N_SUCCESS;
}

/* Define the extension type */
const s2n_extension_type s2n_encrypted_attestation_evidence_extension = {
    .iana_value = TLS_EXTENSION_ATTESTATION_EVIDENCE,
    .is_response = false,
    .send = s2n_encrypted_attestation_evidence_extension_send,
    .recv = s2n_encrypted_attestation_evidence_extension_recv,
    .should_send = s2n_encrypted_attestation_evidence_should_send,
    .if_missing = NULL,
};