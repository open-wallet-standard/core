#ifndef OWS_GO_ERROR_H
#define OWS_GO_ERROR_H

#include <stdint.h>

typedef int32_t ows_go_error_code_t;

#define OWS_GO_OK              0
#define OWS_GO_ERR_WALLET_NOT_FOUND  1
#define OWS_GO_ERR_WALLET_AMBIGUOUS  2
#define OWS_GO_ERR_WALLET_EXISTS    3
#define OWS_GO_ERR_INVALID_INPUT     4
#define OWS_GO_ERR_BROADCAST_FAILED  5
#define OWS_GO_ERR_CRYPTO           6
#define OWS_GO_ERR_SIGNER            7
#define OWS_GO_ERR_MNEMONIC          8
#define OWS_GO_ERR_HD                9
#define OWS_GO_ERR_CORE              10
#define OWS_GO_ERR_IO                11
#define OWS_GO_ERR_JSON              12
#define OWS_GO_ERR_UNKNOWN           99

#endif // OWS_GO_ERROR_H
