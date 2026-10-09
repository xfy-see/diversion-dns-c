#include <stdint.h>
struct nfgenmsg { uint8_t nfgen_family,version; uint16_t res_id; };
#define NFNL_SUBSYS_NFTABLES 10
#define NFNETLINK_V0 0
#define NFNL_MSG_BATCH_BEGIN 16
#define NFNL_MSG_BATCH_END 17
#define NFNL_BATCH_GENID 1
