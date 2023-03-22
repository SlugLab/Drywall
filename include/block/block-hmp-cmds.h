/*
 * HMP commands related to the block layer
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2020 Red Hat, Inc.
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef BLOCK_BLOCK_HMP_CMDS_H
#define BLOCK_BLOCK_HMP_CMDS_H

#include "qemu/coroutine.h"

void hmp_drive_add(Monitor *mon, const QDict *qdict);

void hmp_commit(Monitor *mon, const QDict *qdict);
void hmp_drive_del(Monitor *mon, const QDict *qdict);

void hmp_drive_mirror(Monitor *mon, const QDict *qdict);
void hmp_drive_backup(Monitor *mon, const QDict *qdict);

void hmp_block_job_set_speed(Monitor *mon, const QDict *qdict);
void hmp_block_job_cancel(Monitor *mon, const QDict *qdict);
void hmp_block_job_pause(Monitor *mon, const QDict *qdict);
void hmp_block_job_resume(Monitor *mon, const QDict *qdict);
void hmp_block_job_complete(Monitor *mon, const QDict *qdict);

void hmp_snapshot_blkdev(Monitor *mon, const QDict *qdict);
void hmp_snapshot_blkdev_internal(Monitor *mon, const QDict *qdict);
void hmp_snapshot_delete_blkdev_internal(Monitor *mon, const QDict *qdict);

void hmp_nbd_server_start(Monitor *mon, const QDict *qdict);
void hmp_nbd_server_add(Monitor *mon, const QDict *qdict);
void hmp_nbd_server_remove(Monitor *mon, const QDict *qdict);
void hmp_nbd_server_stop(Monitor *mon, const QDict *qdict);

void coroutine_fn hmp_block_resize(Monitor *mon, const QDict *qdict);
void hmp_block_stream(Monitor *mon, const QDict *qdict);
void hmp_block_passwd(Monitor *mon, const QDict *qdict);
void hmp_block_set_io_throttle(Monitor *mon, const QDict *qdict);
void hmp_eject(Monitor *mon, const QDict *qdict);

// void hmp_get_clocks_in_guest(Monitor *mon, const QDict *qdict);
// void hmp_get_clocks_of_host(Monitor *mon, const QDict *qdict);
// void hmp_get_spp_violation_count(Monitor *mon, const QDict *qdict);
// void hmp_get_spp_misconfig_count(Monitor *mon, const QDict *qdict);
// void hmp_dirty_log_start(Monitor *mon, const QDict *qdict);
// void hmp_spp_dirty_log_start(Monitor *mon, const QDict *qdict);
// void hmp_sppon(Monitor *mon, const QDict *qdict);
// void hmp_get_iteration_size(Monitor *mon, const QDict *qdict);
// void hmp_init_mycache(Monitor *mon, const QDict *qdict);
// void hmp_get_dirty_size(Monitor *mon, const QDict *qdict);

// void hmp_run_for_instruction(Monitor *mon, const QDict *qdict);
void hmp_qemu_io(Monitor *mon, const QDict *qdict);

void hmp_info_block(Monitor *mon, const QDict *qdict);
void hmp_info_blockstats(Monitor *mon, const QDict *qdict);
void hmp_info_block_jobs(Monitor *mon, const QDict *qdict);
void hmp_info_snapshots(Monitor *mon, const QDict *qdict);

#endif
