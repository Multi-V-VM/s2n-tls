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

/* Should the server respond with attestation */
static bool s2n_server_attestation_request_should_send(struct s2n_connection *conn)
{
    return conn && conn->attestation_context
            && conn->attestation_context->attestation_requested;
}

/* Send the attestation request extension in the server hello */
int s2n_server_attestation_request_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(conn->attestation_context);

    /* Write the attestation type that server will use */
    POSIX_GUARD(s2n_stuffer_write_uint16(out, conn->attestation_context->attestation_type));

    return S2N_SUCCESS;
}

/* Process the attestation extension from server hello */
int s2n_server_attestation_request_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(extension);

    /* Ensure client requested attestation */
    POSIX_ENSURE(conn->attestation_context, S2N_ERR_MISSING_EXTENSION);
    POSIX_ENSURE(conn->attestation_context->attestation_requested, S2N_ERR_MISSING_EXTENSION);

    uint16_t attestation_type;
    POSIX_GUARD(s2n_stuffer_read_uint16(extension, &attestation_type));

    /* Validate the attestation type */
    POSIX_ENSURE(attestation_type > S2N_ATTESTATION_NONE && attestation_type < S2N_ATTESTATION_MAX,
            S2N_ERR_INVALID_ATTESTATION_TYPE);

    /* Only accept attestation type that matches request */
    POSIX_ENSURE(attestation_type == conn->attestation_context->attestation_type,
            S2N_ERR_INVALID_ATTESTATION_TYPE);

    return S2N_SUCCESS;
}

/* Define the extension type */
const s2n_extension_type s2n_server_attestation_request_extension = {
    .iana_value = TLS_EXTENSION_ATTESTATION_REQUEST,
    .is_response = true,
    .send = s2n_server_attestation_request_extension_send,
    .recv = s2n_server_attestation_request_extension_recv,
    .should_send = s2n_server_attestation_request_should_send,
    .if_missing = NULL,
};