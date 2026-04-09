/*
 *
 * honggfuzz - architecture dependent code (LINUX/PERF)
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#include "perf.h"

#include <asm/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sysctl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "bts_modules.h"
#include "pt.h"

#define _HF_PERF_MAP_SZ (1024 * 512)
/* PERF_TYPE for Intel_PT/BTS -1 if none */
static int32_t perfIntelPtPerfType  = -1;
static int32_t perfIntelBtsPerfType = -1;

static inline bool arch_perfBtsModuleFilterEnabled(const run_t* run) {
    return run->global->arch_linux.btsModuleNamesCnt != 0U;
}

static inline bool arch_perfBtsModuleStatsEnabled(const run_t* run) {
    return run->global->arch_linux.btsModuleStatsFd != -1;
}

static inline bool arch_perfBtsModuleTrackingEnabled(const run_t* run) {
    return arch_perfBtsModuleFilterEnabled(run) || arch_perfBtsModuleStatsEnabled(run);
}

static bool arch_perfBtsOpenModulesShm(run_t* run) {
    if (run->arch_linux.btsModuleShm != NULL) {
        return true;
    }

    char name[HF_BTS_MODULES_SHM_NAME_SIZE];
    int  len = snprintf(name, sizeof(name), "%s%d", HF_BTS_MODULES_SHM_NAME_PREFIX, run->pid);
    if (len < 0 || (size_t)len >= sizeof(name)) {
        if (!run->arch_linux.btsModuleFilterErrorLogged) {
            LOG_W("BTS module SHM name truncated for pid=%d", (int)run->pid);
            run->arch_linux.btsModuleFilterErrorLogged = true;
        }
        return false;
    }

    int fd = shm_open(name, O_RDONLY, 0);
    if (fd == -1) {
        if (errno != ENOENT && !run->arch_linux.btsModuleFilterErrorLogged) {
            PLOG_W("shm_open('%s', O_RDONLY)", name);
            run->arch_linux.btsModuleFilterErrorLogged = true;
        }
        return false;
    }

    void* map = mmap(NULL, sizeof(hf_bts_module_shm_t), PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        if (!run->arch_linux.btsModuleFilterErrorLogged) {
            PLOG_W("mmap(BTS module SHM, pid=%d)", (int)run->pid);
            run->arch_linux.btsModuleFilterErrorLogged = true;
        }
        close(fd);
        return false;
    }

    run->arch_linux.btsModuleShm   = map;
    run->arch_linux.btsModuleShmFd = fd;
    return true;
}

static void arch_perfBtsRefreshModulesFilter(run_t* run) {
    if (!arch_perfBtsModuleTrackingEnabled(run)) {
        return;
    }
    if (!arch_perfBtsOpenModulesShm(run)) {
        return;
    }

    hf_bts_module_shm_t* shm = (hf_bts_module_shm_t*)run->arch_linux.btsModuleShm;
    if (ATOMIC_GET(shm->magic) != HF_BTS_MODULES_SHM_MAGIC ||
        ATOMIC_GET(shm->version) != HF_BTS_MODULES_SHM_VERSION) {
        if (!run->arch_linux.btsModuleFilterErrorLogged) {
            LOG_W("Unexpected BTS module SHM header for pid=%d", (int)run->pid);
            run->arch_linux.btsModuleFilterErrorLogged = true;
        }
        return;
    }
    if (ATOMIC_GET(shm->ready) == 0U) {
        return;
    }

    bool   matched[_HF_BTS_MODULE_FILTER_MAX] = { false };
    size_t entryCnt                           = ATOMIC_GET(shm->count);
    if (entryCnt > HF_BTS_MODULES_SHM_MAX_ENTRIES) {
        entryCnt = HF_BTS_MODULES_SHM_MAX_ENTRIES;
    }
    if (run->arch_linux.btsModuleFilterReady &&
        run->arch_linux.btsModuleShmCount == entryCnt) {
        return;
    }

    if (arch_perfBtsModuleStatsEnabled(run)) {
        MX_SCOPED_LOCK(&run->global->mutex.feedback);
        run->global->arch_linux.btsModuleStatsCnt = entryCnt;
    }

    run->arch_linux.btsLoadedModuleCnt = entryCnt;
    run->arch_linux.btsModuleRangeCnt  = 0;
    for (size_t entryIdx = 0; entryIdx < entryCnt; entryIdx++) {
        bool allowed = !arch_perfBtsModuleFilterEnabled(run);

        for (size_t modIdx = 0; modIdx < run->global->arch_linux.btsModuleNamesCnt; modIdx++) {
            if (strcmp(shm->entries[entryIdx].name, run->global->arch_linux.btsModuleNames[modIdx]) !=
                0) {
                continue;
            }
            matched[modIdx] = true;
            allowed         = true;
            break;
        }

        run->arch_linux.btsLoadedModules[entryIdx].start     = shm->entries[entryIdx].start;
        run->arch_linux.btsLoadedModules[entryIdx].end       = shm->entries[entryIdx].end;
        run->arch_linux.btsLoadedModules[entryIdx].statsSlot = (int32_t)entryIdx;
        run->arch_linux.btsLoadedModules[entryIdx].allowed   = allowed;
        snprintf(run->arch_linux.btsLoadedModules[entryIdx].name,
            sizeof(run->arch_linux.btsLoadedModules[entryIdx].name), "%s",
            shm->entries[entryIdx].name);

        if (arch_perfBtsModuleStatsEnabled(run)) {
            MX_SCOPED_LOCK(&run->global->mutex.feedback);
            snprintf(run->global->arch_linux.btsModuleStatsNames[entryIdx],
                sizeof(run->global->arch_linux.btsModuleStatsNames[entryIdx]), "%s",
                shm->entries[entryIdx].name);
            run->global->arch_linux.btsModuleStatsAllowed[entryIdx] = allowed ? 1U : 0U;
        }

        if (!allowed || !arch_perfBtsModuleFilterEnabled(run)) {
            continue;
        }
        if (run->arch_linux.btsModuleRangeCnt >= ARRAYSIZE(run->arch_linux.btsModuleRanges)) {
            if (!run->arch_linux.btsModuleFilterWarned) {
                LOG_W("Too many BTS module ranges for pid=%d, truncating to %u entries",
                    (int)run->pid, _HF_BTS_MODULE_FILTER_MAX);
                run->arch_linux.btsModuleFilterWarned = true;
            }
            break;
        }

        run->arch_linux.btsModuleRanges[run->arch_linux.btsModuleRangeCnt].start =
            shm->entries[entryIdx].start;
        run->arch_linux.btsModuleRanges[run->arch_linux.btsModuleRangeCnt].end =
            shm->entries[entryIdx].end;
        run->arch_linux.btsModuleRangeCnt++;
    }

    for (size_t modIdx = 0; modIdx < run->global->arch_linux.btsModuleNamesCnt; modIdx++) {
        if (!matched[modIdx]) {
            LOG_W("Requested BTS module '%s' was not exported by pid=%d",
                run->global->arch_linux.btsModuleNames[modIdx], (int)run->pid);
        }
    }

    LOG_I("Loaded %zu BTS module(s) for pid=%d (%zu filter range(s))",
        run->arch_linux.btsLoadedModuleCnt, (int)run->pid, run->arch_linux.btsModuleRangeCnt);
    run->arch_linux.btsModuleShmCount    = (uint32_t)entryCnt;
    run->arch_linux.btsModuleFilterReady = true;
}

static inline int32_t arch_perfBtsFindModuleSlot(const run_t* run, uint64_t pc) {
    for (size_t i = 0; i < run->arch_linux.btsLoadedModuleCnt; i++) {
        if (pc >= run->arch_linux.btsLoadedModules[i].start &&
            pc < run->arch_linux.btsLoadedModules[i].end) {
            return (int32_t)i;
        }
    }
    return -1;
}

static inline bool arch_perfBtsSlotAllowed(const run_t* run, int32_t slot) {
    return slot >= 0 && run->arch_linux.btsLoadedModules[slot].allowed;
}

static void arch_perfBtsRecordEdgeStats(
    run_t* run, int32_t fromSlot, int32_t toSlot, bool allowedEdge) {
    if (!arch_perfBtsModuleStatsEnabled(run)) {
        return;
    }

    bool touchedModule = false;
    if (fromSlot >= 0) {
        touchedModule = true;
        if (allowedEdge) {
            ATOMIC_PRE_INC(run->global->arch_linux.btsModuleAcceptedPerModule[fromSlot]);
        } else {
            ATOMIC_PRE_INC(run->global->arch_linux.btsModuleDiscardedPerModule[fromSlot]);
        }
    }
    if (toSlot >= 0 && toSlot != fromSlot) {
        touchedModule = true;
        if (allowedEdge) {
            ATOMIC_PRE_INC(run->global->arch_linux.btsModuleAcceptedPerModule[toSlot]);
        } else {
            ATOMIC_PRE_INC(run->global->arch_linux.btsModuleDiscardedPerModule[toSlot]);
        }
    }

    if (allowedEdge) {
        if (touchedModule) {
            ATOMIC_PRE_INC(run->global->arch_linux.btsModuleAcceptedTotal);
        }
    } else {
        ATOMIC_PRE_INC(run->global->arch_linux.btsModuleDiscardedTotal);
        if (!touchedModule) {
            ATOMIC_PRE_INC(run->global->arch_linux.btsModuleDiscardedUnknown);
        }
    }
}

static void arch_perfBtsMaybeWriteModuleStats(run_t* run) {
    if (!arch_perfBtsModuleStatsEnabled(run)) {
        return;
    }

    const time_t now = time(NULL);
    time_t       lastWrite = ATOMIC_GET(run->global->arch_linux.btsModuleStatsLastWrite);
    if ((uint64_t)(now - lastWrite) < run->global->arch_linux.btsModuleStatsInterval) {
        return;
    }
    if (!__atomic_compare_exchange_n(&run->global->arch_linux.btsModuleStatsLastWrite, &lastWrite,
            now, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        return;
    }

    MX_SCOPED_LOCK(&run->global->mutex.feedback);

    dprintf(run->global->arch_linux.btsModuleStatsFd,
        "snapshot unix_time=%ld total_module_edges=%" PRIu64 " total_discarded=%" PRIu64
        " discarded_unknown=%" PRIu64 " modules=%zu\n",
        (long)now, ATOMIC_GET(run->global->arch_linux.btsModuleAcceptedTotal),
        ATOMIC_GET(run->global->arch_linux.btsModuleDiscardedTotal),
        ATOMIC_GET(run->global->arch_linux.btsModuleDiscardedUnknown),
        ATOMIC_GET(run->global->arch_linux.btsModuleStatsCnt));

    const size_t moduleCnt = ATOMIC_GET(run->global->arch_linux.btsModuleStatsCnt);
    for (size_t i = 0; i < moduleCnt; i++) {
        if (run->global->arch_linux.btsModuleStatsNames[i][0] == '\0') {
            continue;
        }
        dprintf(run->global->arch_linux.btsModuleStatsFd,
            "module name=%s allowed=%u accepted=%" PRIu64 " discarded=%" PRIu64 "\n",
            run->global->arch_linux.btsModuleStatsNames[i],
            (unsigned)ATOMIC_GET(run->global->arch_linux.btsModuleStatsAllowed[i]),
            ATOMIC_GET(run->global->arch_linux.btsModuleAcceptedPerModule[i]),
            ATOMIC_GET(run->global->arch_linux.btsModuleDiscardedPerModule[i]));
    }
    dprintf(run->global->arch_linux.btsModuleStatsFd, "\n");
}

static inline bool arch_perfBtsEdgeAllowed(const run_t* run, uint64_t from, uint64_t to) {
    for (size_t i = 0; i < run->arch_linux.btsModuleRangeCnt; i++) {
        if ((from >= run->arch_linux.btsModuleRanges[i].start &&
                from < run->arch_linux.btsModuleRanges[i].end) ||
            (to >= run->arch_linux.btsModuleRanges[i].start &&
                to < run->arch_linux.btsModuleRanges[i].end)) {
            return true;
        }
    }
    return false;
}

#if defined(PERF_ATTR_SIZE_VER5)
__attribute__((hot)) static inline void arch_perfBtsCount(run_t* run) {
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->arch_linux.perfMmapBuf;
    struct bts_branch {
        uint64_t from;
        uint64_t to;
        uint64_t misc;
    };

    uint64_t           aux_head = ATOMIC_GET(pem->aux_head);
    struct bts_branch* br       = (struct bts_branch*)run->arch_linux.perfMmapAux;
    if (arch_perfBtsModuleTrackingEnabled(run)) {
        arch_perfBtsRefreshModulesFilter(run);
    }
    for (; br < ((struct bts_branch*)(run->arch_linux.perfMmapAux + aux_head)); br++) {
        /*
         * Kernel sometimes reports branches from the kernel (iret), we are not interested in that
         * as it makes the whole concept of unique branch counting less predictable
         */
        if (!run->global->arch_linux.kernelOnly &&
            (__builtin_expect(br->from > 0xFFFFFFFF00000000, false) ||
                __builtin_expect(br->to > 0xFFFFFFFF00000000, false))) {
            LOG_D("Adding branch %#018" PRIx64 " - %#018" PRIx64, br->from, br->to);
            continue;
        }
        if (br->from >= run->global->arch_linux.dynamicCutOffAddr ||
            br->to >= run->global->arch_linux.dynamicCutOffAddr) {
            continue;
        }

        int32_t fromSlot = -1;
        int32_t toSlot   = -1;
        if (arch_perfBtsModuleStatsEnabled(run)) {
            fromSlot = arch_perfBtsFindModuleSlot(run, br->from);
            toSlot   = arch_perfBtsFindModuleSlot(run, br->to);
        }

        bool allowedEdge = true;
        if (arch_perfBtsModuleFilterEnabled(run)) {
            allowedEdge = run->arch_linux.btsModuleFilterReady &&
                          (arch_perfBtsSlotAllowed(run, fromSlot) ||
                              arch_perfBtsSlotAllowed(run, toSlot) ||
                              (!arch_perfBtsModuleStatsEnabled(run) &&
                                  arch_perfBtsEdgeAllowed(run, br->from, br->to)));
            arch_perfBtsRecordEdgeStats(run, fromSlot, toSlot, allowedEdge);
            if (!allowedEdge) {
                continue;
            }
        } else if (arch_perfBtsModuleStatsEnabled(run)) {
            arch_perfBtsRecordEdgeStats(run, fromSlot, toSlot, true);
        }

        register size_t pos = ((br->from << 12) ^ (br->to & 0xFFF));
        pos &= _HF_PERF_BITMAP_BITSZ_MASK;

        register bool prev = ATOMIC_BITMAP_SET(run->global->feedback.covFeedbackMap->bbMapPc, pos);
        if (!prev) {
            run->hwCnts.newBBCnt++;
        }
    }
    arch_perfBtsMaybeWriteModuleStats(run);
}
#endif /* defined(PERF_ATTR_SIZE_VER5) */

static inline void arch_perfMmapParse(run_t* run HF_ATTR_UNUSED) {
#if defined(PERF_ATTR_SIZE_VER5)
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->arch_linux.perfMmapBuf;
    if (pem->aux_head == pem->aux_tail) {
        return;
    }
    if (pem->aux_head < pem->aux_tail) {
        LOG_F("The PERF AUX data has been overwritten. The AUX buffer is too small");
    }
    if (pem->aux_head > _HF_PERF_AUX_SZ) {
        LOG_W("The PERF AUX data (%lu) is larger than the buffer size (%u). Skipping analysis.",
            (unsigned long)pem->aux_head, _HF_PERF_AUX_SZ);
        return;
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        arch_perfBtsCount(run);
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        arch_ptAnalyze(run);
    }
#endif /* defined(PERF_ATTR_SIZE_VER5) */
}

static long perf_event_open(
    struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, (uintptr_t)pid, (uintptr_t)cpu,
        (uintptr_t)group_fd, (uintptr_t)flags);
}

static bool arch_perfCreate(run_t* run, pid_t pid, dynFileMethod_t method, int* perfFd) {
    LOG_D("Enabling PERF for pid=%d method=%x", pid, method);

    if (*perfFd != -1) {
        LOG_F("The PERF FD is already initialized, possibly conflicting perf types enabled");
    }

    if ((method & _HF_DYNFILE_BTS_EDGE) && perfIntelBtsPerfType == -1) {
        LOG_F("Intel BTS events (new type) are not supported on this platform");
    }
    if ((method & _HF_DYNFILE_IPT_BLOCK) && perfIntelPtPerfType == -1) {
        LOG_F("Intel PT events are not supported on this platform");
    }

    struct perf_event_attr pe = {};
    pe.size                   = sizeof(struct perf_event_attr);
    if (run->global->arch_linux.kernelOnly) {
        pe.exclude_user = 1;
    } else {
        pe.exclude_kernel = 1;
    }
    pe.disabled = 1;
    if (!run->global->exe.persistent) {
        pe.enable_on_exec = 1;
    }
    pe.exclude_hv = 1;
    pe.type       = PERF_TYPE_HARDWARE;

    switch (method) {
    case _HF_DYNFILE_INSTR_COUNT:
        LOG_D("Using: PERF_COUNT_HW_INSTRUCTIONS for pid=%d", (int)pid);
        pe.config  = PERF_COUNT_HW_INSTRUCTIONS;
        pe.inherit = 1;
        break;
    case _HF_DYNFILE_BRANCH_COUNT:
        LOG_D("Using: PERF_COUNT_HW_BRANCH_INSTRUCTIONS for pid=%d", (int)pid);
        pe.config  = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.inherit = 1;
        break;
    case _HF_DYNFILE_BTS_EDGE:
        LOG_D("Using: (Intel BTS) type=%" PRIu32 " for pid=%d", perfIntelBtsPerfType, (int)pid);
        pe.type = perfIntelBtsPerfType;
        break;
    case _HF_DYNFILE_IPT_BLOCK:
        LOG_D("Using: (Intel PT) type=%" PRIu32 " for pid=%d", perfIntelPtPerfType, (int)pid);
        pe.type   = perfIntelPtPerfType;
        pe.config = RTIT_CTL_DISRETC;
        break;
    default:
        LOG_E("Unknown perf mode: '%d' for pid=%d", method, (int)pid);
        return false;
        break;
    }

#if !defined(PERF_FLAG_FD_CLOEXEC)
#define PERF_FLAG_FD_CLOEXEC 0
#endif
    *perfFd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (*perfFd == -1) {
        PLOG_E("perf_event_open() failed");
        return false;
    }

    if (method != _HF_DYNFILE_BTS_EDGE && method != _HF_DYNFILE_IPT_BLOCK) {
        return true;
    }
#if defined(PERF_ATTR_SIZE_VER5)
    if ((run->arch_linux.perfMmapBuf = mmap(NULL, _HF_PERF_MAP_SZ + getpagesize(),
             PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, 0)) == MAP_FAILED) {
        run->arch_linux.perfMmapBuf = NULL;
        PLOG_W("mmap(mmapBuf) failed, sz=%zu, try increasing the kernel.perf_event_mlock_kb sysctl "
               "(up to even 300000000)",
            (size_t)_HF_PERF_MAP_SZ + getpagesize());
        close(*perfFd);
        *perfFd = -1;
        return false;
    }

    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->arch_linux.perfMmapBuf;
    pem->aux_offset                  = pem->data_offset + pem->data_size;
    pem->aux_size                    = _HF_PERF_AUX_SZ;
    if ((run->arch_linux.perfMmapAux = mmap(
             NULL, pem->aux_size, PROT_READ, MAP_SHARED, *perfFd, pem->aux_offset)) == MAP_FAILED) {
        munmap(run->arch_linux.perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
        run->arch_linux.perfMmapBuf = NULL;
        run->arch_linux.perfMmapAux = NULL;
        PLOG_W(
            "mmap(mmapAuxBuf) failed, try increasing the kernel.perf_event_mlock_kb sysctl (up to "
            "even 300000000)");
        close(*perfFd);
        *perfFd = -1;
        return false;
    }
#else  /* defined(PERF_ATTR_SIZE_VER5) */
    LOG_F("Your <linux/perf_event.h> includes are too old to support Intel PT/BTS");
#endif /* defined(PERF_ATTR_SIZE_VER5) */

    return true;
}

bool arch_perfOpen(run_t* run) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        return true;
    }

    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        if (!arch_perfCreate(run, run->pid, _HF_DYNFILE_INSTR_COUNT, &run->arch_linux.cpuInstrFd)) {
            LOG_E("Cannot set up perf for pid=%d (_HF_DYNFILE_INSTR_COUNT)", (int)run->pid);
            goto out;
        }
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        if (!arch_perfCreate(
                run, run->pid, _HF_DYNFILE_BRANCH_COUNT, &run->arch_linux.cpuBranchFd)) {
            LOG_E("Cannot set up perf for pid=%d (_HF_DYNFILE_BRANCH_COUNT)", (int)run->pid);
            goto out;
        }
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        if (!arch_perfCreate(run, run->pid, _HF_DYNFILE_BTS_EDGE, &run->arch_linux.cpuIptBtsFd)) {
            LOG_E("Cannot set up perf for pid=%d (_HF_DYNFILE_BTS_EDGE)", (int)run->pid);
            goto out;
        }
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        if (!arch_perfCreate(run, run->pid, _HF_DYNFILE_IPT_BLOCK, &run->arch_linux.cpuIptBtsFd)) {
            LOG_E("Cannot set up perf for pid=%d (_HF_DYNFILE_IPT_BLOCK)", (int)run->pid);
            goto out;
        }
    }

    return true;

out:
    close(run->arch_linux.cpuInstrFd);
    run->arch_linux.cpuInstrFd = -1;
    close(run->arch_linux.cpuBranchFd);
    run->arch_linux.cpuBranchFd = -1;
    close(run->arch_linux.cpuIptBtsFd);
    run->arch_linux.cpuIptBtsFd = -1;

    return false;
}

void arch_perfClose(run_t* run) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }

    if (run->arch_linux.btsModuleShm != NULL) {
        munmap(run->arch_linux.btsModuleShm, sizeof(hf_bts_module_shm_t));
        run->arch_linux.btsModuleShm = NULL;
    }
    if (run->arch_linux.btsModuleShmFd != -1) {
        close(run->arch_linux.btsModuleShmFd);
        run->arch_linux.btsModuleShmFd = -1;
    }
    run->arch_linux.btsModuleShmCount        = 0;
    run->arch_linux.btsLoadedModuleCnt       = 0;
    run->arch_linux.btsModuleRangeCnt        = 0;
    run->arch_linux.btsModuleFilterReady     = false;
    run->arch_linux.btsModuleFilterWarned    = false;
    run->arch_linux.btsModuleFilterErrorLogged = false;

    if (run->arch_linux.perfMmapAux != NULL) {
        munmap(run->arch_linux.perfMmapAux, _HF_PERF_AUX_SZ);
        run->arch_linux.perfMmapAux = NULL;
    }
    if (run->arch_linux.perfMmapBuf != NULL) {
        munmap(run->arch_linux.perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
        run->arch_linux.perfMmapBuf = NULL;
    }

    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        close(run->arch_linux.cpuInstrFd);
        run->arch_linux.cpuInstrFd = -1;
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        close(run->arch_linux.cpuBranchFd);
        run->arch_linux.cpuBranchFd = -1;
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        close(run->arch_linux.cpuIptBtsFd);
        run->arch_linux.cpuIptBtsFd = -1;
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        close(run->arch_linux.cpuIptBtsFd);
        run->arch_linux.cpuIptBtsFd = -1;
    }
}

bool arch_perfEnable(run_t* run) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        return true;
    }
    /* It's enabled on exec in such scenario */
    if (!run->global->exe.persistent) {
        return true;
    }

    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        ioctl(run->arch_linux.cpuInstrFd, PERF_EVENT_IOC_ENABLE, 0);
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        ioctl(run->arch_linux.cpuBranchFd, PERF_EVENT_IOC_ENABLE, 0);
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        ioctl(run->arch_linux.cpuIptBtsFd, PERF_EVENT_IOC_ENABLE, 0);
    }
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        ioctl(run->arch_linux.cpuIptBtsFd, PERF_EVENT_IOC_ENABLE, 0);
    }

    return true;
}

static void arch_perfMmapReset(run_t* run) {
    /* smp_mb() required as per /usr/include/linux/perf_event.h */
    wmb();

    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)run->arch_linux.perfMmapBuf;
    ATOMIC_SET(pem->data_head, 0);
    ATOMIC_SET(pem->data_tail, 0);
#if defined(PERF_ATTR_SIZE_VER5)
    ATOMIC_SET(pem->aux_head, 0);
    ATOMIC_SET(pem->aux_tail, 0);
#endif /* defined(PERF_ATTR_SIZE_VER5) */
}

void arch_perfAnalyze(run_t* run) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }

    uint64_t instrCount = 0;
    if ((run->global->feedback.dynFileMethod & _HF_DYNFILE_INSTR_COUNT) &&
        run->arch_linux.cpuInstrFd != -1) {
        ioctl(run->arch_linux.cpuInstrFd, PERF_EVENT_IOC_DISABLE, 0);
        if (files_readFromFd(run->arch_linux.cpuInstrFd, (uint8_t*)&instrCount,
                sizeof(instrCount)) != sizeof(instrCount)) {
            PLOG_E("read(perfFd='%d') failed", run->arch_linux.cpuInstrFd);
        }
        ioctl(run->arch_linux.cpuInstrFd, PERF_EVENT_IOC_RESET, 0);
    }

    uint64_t branchCount = 0;
    if ((run->global->feedback.dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) &&
        run->arch_linux.cpuBranchFd != -1) {
        ioctl(run->arch_linux.cpuBranchFd, PERF_EVENT_IOC_DISABLE, 0);
        if (files_readFromFd(run->arch_linux.cpuBranchFd, (uint8_t*)&branchCount,
                sizeof(branchCount)) != sizeof(branchCount)) {
            PLOG_E("read(perfFd='%d') failed", run->arch_linux.cpuBranchFd);
        }
        ioctl(run->arch_linux.cpuBranchFd, PERF_EVENT_IOC_RESET, 0);
    }

    if ((run->global->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE) &&
        run->arch_linux.cpuIptBtsFd != -1) {
        ioctl(run->arch_linux.cpuIptBtsFd, PERF_EVENT_IOC_DISABLE, 0);
        arch_perfMmapParse(run);
        arch_perfMmapReset(run);
        ioctl(run->arch_linux.cpuIptBtsFd, PERF_EVENT_IOC_RESET, 0);
    }
    if ((run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK) &&
        run->arch_linux.cpuIptBtsFd != -1) {
        ioctl(run->arch_linux.cpuIptBtsFd, PERF_EVENT_IOC_DISABLE, 0);
        arch_perfMmapParse(run);
        arch_perfMmapReset(run);
        ioctl(run->arch_linux.cpuIptBtsFd, PERF_EVENT_IOC_RESET, 0);
    }

    run->hwCnts.cpuInstrCnt  = instrCount;
    run->hwCnts.cpuBranchCnt = branchCount;
}

bool arch_perfInit(honggfuzz_t* hfuzz HF_ATTR_UNUSED) {
    static char const intel_pt_path[]  = "/sys/bus/event_source/devices/intel_pt/type";
    static char const intel_bts_path[] = "/sys/bus/event_source/devices/intel_bts/type";

    if (files_exists(intel_pt_path)) {
        uint8_t buf[256];
        ssize_t sz = files_readFileToBufMax(intel_pt_path, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz]             = '\0';
            perfIntelPtPerfType = (int32_t)strtoul((char*)buf, NULL, 10);
            LOG_D("perfIntelPtPerfType = %" PRIu32, perfIntelPtPerfType);
        }
    }

    if (files_exists(intel_bts_path)) {
        uint8_t buf[256];
        ssize_t sz = files_readFileToBufMax(intel_bts_path, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz]              = '\0';
            perfIntelBtsPerfType = (int32_t)strtoul((char*)buf, NULL, 10);
            LOG_D("perfIntelBtsPerfType = %" PRIu32, perfIntelBtsPerfType);
        }
    }

    perf_ptInit();

    return true;
}
