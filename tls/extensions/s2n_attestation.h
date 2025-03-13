/*
 * The WebAssembly Live Migration Project
 *
 * Copyright 2024 Regents of the Univeristy of California
 * UC Santa Cruz Sluglab.
 */

#pragma once

#include <stdint.h>

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_result.h"

/* Attestation extension type codes */
#define TLS_EXTENSION_ATTESTATION_REQUEST  0xF001
#define TLS_EXTENSION_ATTESTATION_EVIDENCE 0xF002

/* Attestation request modes */
typedef enum {
    S2N_ATTESTATION_NONE = 0,
    S2N_ATTESTATION_SGX = 1,
    S2N_ATTESTATION_TZ = 2,
    S2N_ATTESTATION_CCA = 3,
    S2N_ATTESTATION_SEV = 4,
    S2N_ATTESTATION_TDX = 5,
    S2N_ATTESTATION_MAX
} s2n_attestation_type;

/* Data structure for attestation evidence */
struct s2n_attestation_evidence {
    s2n_attestation_type type;
    struct s2n_blob evidence;
    struct s2n_blob challenge;
};

/* Add attestation flags to connection structure */
struct s2n_attestation_context {
    unsigned attestation_requested : 1;
    unsigned attestation_type_set : 1;
    s2n_attestation_type attestation_type;
    struct s2n_attestation_evidence local_evidence;
    struct s2n_attestation_evidence peer_evidence;
};

/* Client hello callbacks */
extern int s2n_client_attestation_request_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_client_attestation_request_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

/* Server hello callbacks */
extern int s2n_server_attestation_request_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_server_attestation_request_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

/* Encrypted extensions callbacks */
extern int s2n_encrypted_attestation_evidence_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_encrypted_attestation_evidence_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

/* Certificate extension callbacks */
extern int s2n_certificate_attestation_evidence_extension_send(struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_certificate_attestation_evidence_extension_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

/* API functions */
extern S2N_RESULT s2n_connection_set_attestation_type(struct s2n_connection *conn, s2n_attestation_type type);
extern S2N_RESULT s2n_connection_get_attestation_type(struct s2n_connection *conn, s2n_attestation_type *type);
extern S2N_RESULT s2n_connection_set_attestation_evidence(struct s2n_connection *conn, const uint8_t *evidence, uint32_t size);
extern S2N_RESULT s2n_connection_get_peer_attestation_evidence(struct s2n_connection *conn, uint8_t **evidence, uint32_t *size);
extern S2N_RESULT s2n_connection_verify_attestation_evidence(struct s2n_connection *conn);
extern S2N_RESULT s2n_connection_generate_attestation_evidence(struct s2n_connection *conn, const uint8_t *challenge, uint32_t challenge_size);