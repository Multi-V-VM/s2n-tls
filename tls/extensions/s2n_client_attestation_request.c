/*
 * The WebAssembly Live Migration Project
 *
 * Copyright 2024 Regents of the Univeristy of California
 * UC Santa Cruz Sluglab.
 */

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_attestation.h"
#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

/* Send the attestation request extension in the client hello. */
int s2n_client_attestation_request_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(out);

    /* Only send if attestation is requested */
    if (!conn->attestation_context || !conn->attestation_context->attestation_requested) {
        return S2N_SUCCESS;
    }

    /* Write the attestation type to request */
    POSIX_GUARD(s2n_stuffer_write_uint16(out, conn->attestation_context->attestation_type));

    return S2N_SUCCESS;
}

/* Process the attestation request extension from client hello. */
int s2n_client_attestation_request_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(extension);

    /* Allocate attestation context if not already done */
    if (!conn->attestation_context) {
        POSIX_ENSURE_REF(conn->config);
        struct s2n_blob attestation_context = { 0 };
        POSIX_GUARD(s2n_alloc(&attestation_context, sizeof(struct s2n_attestation_context)));
        conn->attestation_context = (struct s2n_attestation_context *) (void *) attestation_context.data;
        POSIX_ENSURE_REF(conn->attestation_context);
        memset(conn->attestation_context, 0, sizeof(struct s2n_attestation_context));
    }

    uint16_t attestation_type;
    POSIX_GUARD(s2n_stuffer_read_uint16(extension, &attestation_type));

    /* Validate the attestation type */
    POSIX_ENSURE(attestation_type > S2N_ATTESTATION_NONE && attestation_type < S2N_ATTESTATION_MAX,
            S2N_ERR_INVALID_ATTESTATION_TYPE);

    conn->attestation_context->attestation_requested = 1;
    conn->attestation_context->attestation_type = (s2n_attestation_type) attestation_type;

    return S2N_SUCCESS;
}

/* Define the extension type */
const s2n_extension_type s2n_client_attestation_request_extension = {
    .iana_value = TLS_EXTENSION_ATTESTATION_REQUEST,
    .is_response = false,
    .send = s2n_client_attestation_request_extension_send,
    .recv = s2n_client_attestation_request_extension_recv,
    .should_send = NULL,
    .if_missing = NULL,
};