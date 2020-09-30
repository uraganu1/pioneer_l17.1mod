/*
 * drivers/thermal/msm/msm_thermal_notify.c
 *
 * Copyright (C) 2013 LGE Inc
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/thermal_notify.h>
#include <linux/notifier.h>
#include <linux/export.h>

static BLOCKING_NOTIFIER_HEAD(thermal_notifier_list);

/**
 *	thermal_register_client - register a client notifier
 *	@nb: notifier block to callback on events
 */
int thermal_register_client(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&thermal_notifier_list, nb);
}
EXPORT_SYMBOL(thermal_register_client);

/**
 *	thermal_unregister_client - unregister a client notifier
 *	@nb: notifier block to callback on events
 */
int thermal_unregister_client(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&thermal_notifier_list, nb);
}
EXPORT_SYMBOL(thermal_unregister_client);

/**
 *	thermal_notifier_call_chain - notify clients on thermal_events
 *	@val: Value passed unmodified to notifier function
 *	@v: pointer passed unmodified to notifier function
 *
 */
int thermal_notifier_call_chain(unsigned long val, void *v)
{
	return blocking_notifier_call_chain(&thermal_notifier_list, val, v);
}
EXPORT_SYMBOL_GPL(thermal_notifier_call_chain);

