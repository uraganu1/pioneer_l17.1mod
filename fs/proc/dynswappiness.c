/*
 * fs/proc/dynswappiness.c
 *
 *
 * Copyright (c) 2020, Andrei Cojocar <cojocar.andrei@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/swap.h>
#include <linux/android_tweaks.h>
#if defined(CONFIG_POWERSUSPEND)
#include <linux/powersuspend.h>
#endif  // CONFIG_POWERSUSPEND

/* Version, author, desc, etc */
#define DRIVER_AUTHOR "Andrei Cojocar <cojocar.andrei@gmail.com>"
#define DRIVER_DESCRIPTION "Dynamic swappiness"
#define DRIVER_VERSION "1.0"
#define LOGTAG "[dynswappiness]: "

#define K(x) ((x) << (PAGE_SHIFT - 10))
#define DEFAULT_DS_STATE 	0
#define MAXIMUM_SWAPPINESS 	100
#define MINIMUM_SWAPPINESS 	0
#define SWAPPINESS_FILE 	"/proc/sys/vm/swappiness"
#define CHK_CRITICAL_TIME	8000
#define CHK_RESTRICTED_TIME 	16000
#define CHK_NORMAL_TIME		32000
#define NO_CHANGES_COUNTER_MAX	128
#define NO_CHANGES_CRITICAL_MAX 8

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPLv2");

static struct delayed_work check_mem_work;
static atomic_t ds_val;
static bool init_chk = true;
static struct mutex ds_lock;
static unsigned int sfp_level = 0;
static unsigned int no_changes_counter = 0;
static unsigned int check_time = CHK_CRITICAL_TIME;
static atomic_t check_time_mul;

static int get_new_swappiness(int level)
{
        if (level < 0)
                return MINIMUM_SWAPPINESS;
        if (level > MAXIMUM_SWAPPINESS)
                return MAXIMUM_SWAPPINESS;
        return level;
}

static void ds_set_swappiness(int c_swappiness, int n_diff)
{
	struct file *f;
	char buf[16];
	mm_segment_t fs;
	int len, level;

	if (((c_swappiness >= MAXIMUM_SWAPPINESS) && (n_diff >= 0)) ||
	   ((c_swappiness <= MINIMUM_SWAPPINESS) && (n_diff <= 0)))
		return;

	level = get_new_swappiness(c_swappiness + n_diff);

	memset(buf, 0, sizeof(buf));

	f = filp_open(SWAPPINESS_FILE, O_WRONLY, 0644);
	if (f == NULL)
		printk(KERN_ALERT "filp_open error!!.\n");
	else {
		len = scnprintf(buf, sizeof(buf), "%d\n", level);
		fs = get_fs();
		set_fs(KERNEL_DS);
		f->f_op->write(f, buf, len, &f->f_pos);
		set_fs(fs);
		filp_close(f, NULL);
	}
	no_changes_counter = 0;
}

static int ds_get_swappiness(void)
{
	struct file *f;
        char buf[16];
        mm_segment_t fs;
        int ret, val;

	memset(buf, 0, sizeof(buf));

	f = filp_open(SWAPPINESS_FILE, O_RDONLY, 0);
	if (f == NULL)
		printk(KERN_ALERT "filp_open error!!.\n");
	else {
		fs = get_fs();
		set_fs(KERNEL_DS);
		f->f_op->read(f, buf, sizeof(buf), &f->f_pos);
		set_fs(fs);
		filp_close(f, NULL);
		ret = kstrtoint(buf, 10, &val);
		if ((ret) || (val < MINIMUM_SWAPPINESS))
			return MINIMUM_SWAPPINESS;
		if (val > MAXIMUM_SWAPPINESS)
			return MAXIMUM_SWAPPINESS;
		return val;

	}
	return MINIMUM_SWAPPINESS;
}

static void check_mem(struct work_struct *work)
{
	struct sysinfo i;
	int swap_total = 0;
	int swap_free = 0;
	int critical_level, restriction_level, normal_level, swap_free_diff, current_swappiness;

	mutex_lock(&ds_lock);
	si_swapinfo(&i);
	swap_total = K(i.totalswap);
	swap_free = K(i.freeswap);
	if (swap_total > 0) {
		if (init_chk) {
			init_chk = false;
		}
		else {
			critical_level = swap_total/8;
			restriction_level = swap_total/4;
			normal_level = swap_total/2;
			swap_free_diff = sfp_level - swap_free;
			current_swappiness = ds_get_swappiness();
			no_changes_counter++;

			if (swap_free >= normal_level) {
				if (current_swappiness != MAXIMUM_SWAPPINESS)
					ds_set_swappiness(MAXIMUM_SWAPPINESS-1, 1);
				check_time = CHK_NORMAL_TIME;
				no_changes_counter = 0;
			}
			else if (swap_free <= critical_level) {
				if (swap_free_diff == 0) {
                                        if (no_changes_counter > NO_CHANGES_CRITICAL_MAX)
                                                ds_set_swappiness(current_swappiness, -4);
                                } else if (swap_free_diff > 0) {
                			if (swap_free_diff > swap_total/16) {
						ds_set_swappiness(current_swappiness, -16);
					}
					else if (swap_free_diff > swap_total/32) {
						ds_set_swappiness(current_swappiness, -8);
					}
					else {
						ds_set_swappiness(current_swappiness, -4);
					}
				}
				check_time = CHK_CRITICAL_TIME;
			}
			else if (swap_free < restriction_level) {
				if (swap_free_diff >= 0) {
                                        if (swap_free_diff > swap_total/16) {
                                                ds_set_swappiness(current_swappiness, -4);
                                        }
                                        else if (swap_free_diff > swap_total/32) {
                                                ds_set_swappiness(current_swappiness, -2);
                                        }
                                        else if (swap_free_diff > swap_total/64) {
                                                ds_set_swappiness(current_swappiness, -1);
                                        }
                                }
                                else {
					swap_free_diff = swap_free - sfp_level;
                                        if (swap_free_diff > swap_total/16) {
                                                ds_set_swappiness(current_swappiness, +4);
                                        }
                                        else if (swap_free_diff > swap_total/32) {
                                                ds_set_swappiness(current_swappiness, +2);
                                        }
                                        else if (swap_free_diff > swap_total/64) {
                                                ds_set_swappiness(current_swappiness, +1);
                                        }
                                }
				if (no_changes_counter > NO_CHANGES_COUNTER_MAX)
					ds_set_swappiness(current_swappiness, +1);
                                check_time = CHK_RESTRICTED_TIME;
			}
			else {
				if (swap_free_diff >= 0) {
					if (swap_free_diff > swap_total/16) {
                                                ds_set_swappiness(current_swappiness, -2);
                                        }
                                        else if (swap_free_diff > swap_total/32) {
                                                ds_set_swappiness(current_swappiness, -1);
                                        }
				}
				else {
					swap_free_diff = swap_free - sfp_level;
					if (swap_free_diff > swap_total/16) {
                                                ds_set_swappiness(current_swappiness, +2);
                                        }
                                        else if (swap_free_diff > swap_total/32) {
                                                ds_set_swappiness(current_swappiness, +1);
                                        }
				}
				if (no_changes_counter > NO_CHANGES_COUNTER_MAX)
					ds_set_swappiness(current_swappiness, +2);
				check_time = CHK_NORMAL_TIME;
			}
		}
		sfp_level = swap_free;
		queue_delayed_work(system_power_efficient_wq,
                                   &check_mem_work, msecs_to_jiffies(check_time * atomic_read(&check_time_mul)));
	}
	mutex_unlock(&ds_lock);
}

static void ds_set_state(int state)
{
	int val = atomic_read(&ds_val);
	if (val != state) {
		cancel_delayed_work_sync(&check_mem_work);
		if (state == 0) {
			ds_set_swappiness(MAXIMUM_SWAPPINESS-1, 1);
			init_chk = true;
		}
		else {
			queue_delayed_work(system_power_efficient_wq,
                                           &check_mem_work, CHK_CRITICAL_TIME);
		}
		atomic_set(&ds_val, val);
	}
}

static ssize_t fs_dynswappiness_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	size_t count = 0;

        count += sprintf(buf, "%d\n", (int)atomic_read(&ds_val));
        return count;
}

static ssize_t fs_dynswappiness_dump(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        int r, val;

        r = kstrtoint(buf, 10, &val);
        if ((r) || (val < 0)) {
                return -EINVAL;
        }
        if (val > 1) {
                val = 1;
        }

        ds_set_state(val);

        return count;
}
static DEVICE_ATTR(dynswappiness, 0644, fs_dynswappiness_show, fs_dynswappiness_dump);

#ifdef CONFIG_POWERSUSPEND
static void __ref dynswappiness_suspend(struct power_suspend *handler)
{
	atomic_set(&check_time_mul, 8);
}
static void __ref dynswappiness_resume(struct power_suspend *handler)
{
	atomic_set(&check_time_mul, 1);
}

static struct power_suspend dynswappiness_power_suspend_driver = {
        .suspend = dynswappiness_suspend,
        .resume = dynswappiness_resume,
};
#endif

static int __init dynswappiness_init(void)
{
	int ret = 0;

	atomic_set(&ds_val, DEFAULT_DS_STATE);
	atomic_set(&check_time_mul, 1);
	init_chk = true;

	if (android_tweaks_kfpobj == NULL) {
		android_tweaks_kfpobj = kobject_create_and_add("android_tweaks", NULL) ;
	}
	if (android_tweaks_kfpobj == NULL) {
		pr_warn("%s: android_tweaks_kobj create_and_add failed\n", __func__);
		ret = -ENODEV;
	}
	else {
		ret = sysfs_create_file(android_tweaks_kfpobj, &dev_attr_dynswappiness.attr);
		if (ret) {
                        pr_warn("%s: sysfs_create_file failed for dimadjust\n", __func__);
                }
	}

	if (ret == 0) {
		mutex_init(&ds_lock);
		INIT_DELAYED_WORK(&check_mem_work, check_mem);
#if defined(CONFIG_POWERSUSPEND)
        	register_power_suspend(&dynswappiness_power_suspend_driver);
#endif  // CONFIG_POWERSUSPEND
		if (1 == atomic_read(&ds_val)) {
			queue_delayed_work(system_power_efficient_wq,
                                   &check_mem_work, msecs_to_jiffies(CHK_NORMAL_TIME));
		}
	}
	return 0;
}

static void __exit dynswappiness_exit(void)
{
#if defined(CONFIG_POWERSUSPEND)
        unregister_power_suspend(&dynswappiness_power_suspend_driver);
#endif  // CONFIG_POWERSUSPEND
	cancel_delayed_work_sync(&check_mem_work);
	mutex_destroy(&ds_lock);
}

module_init(dynswappiness_init);
module_exit(dynswappiness_exit);

