/*
 *
 * honggfuzz - BTS module filter shared memory layout
 * -----------------------------------------
 *
 */

#ifndef _HF_LINUX_BTS_MODULES_H_
#define _HF_LINUX_BTS_MODULES_H_

#include <stdint.h>

#define HF_BTS_MODULES_SHM_MAGIC       0x4846424dU
#define HF_BTS_MODULES_SHM_VERSION     1U
#define HF_BTS_MODULES_SHM_NAME_PREFIX "/hf_bts_modules_"
#define HF_BTS_MODULES_SHM_NAME_SIZE   64U
#define HF_BTS_MODULES_SHM_MAX_ENTRIES 2048U
#define HF_BTS_MODULES_NAME_MAX        64U

typedef struct {
    uint64_t start;
    uint64_t end;
    char     name[HF_BTS_MODULES_NAME_MAX];
} hf_bts_module_entry_t;

typedef struct {
    uint32_t              magic;
    uint32_t              version;
    uint32_t              ready;
    uint32_t              count;
    hf_bts_module_entry_t entries[HF_BTS_MODULES_SHM_MAX_ENTRIES];
} hf_bts_module_shm_t;

#endif /* _HF_LINUX_BTS_MODULES_H_ */
