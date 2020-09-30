/*
 * Author: Alucard_24@XDA+AndreiC
 *
 * Copyright 2020 Alucard_24@XDA+AndreiC
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/jiffies.h>
#include <linux/kernel_stat.h>
#include <linux/tick.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/slab.h>
#ifdef CONFIG_THERMAL_NOTIFICATION
#include <linux/thermal_notify.h>
#endif

#if defined(CONFIG_POWERSUSPEND)
#include <linux/powersuspend.h>
#endif  // CONFIG_POWERSUSPEND

struct hotplug_cpuinfo {
#ifndef CONFIG_ALUCARD_HOTPLUG_USE_CPU_UTIL
	u64 prev_cpu_wall;
	u64 prev_cpu_idle;
#endif
	unsigned int up_load;
	unsigned int down_load;
	unsigned int up_freq;
	unsigned int down_freq;
	unsigned int up_rq;
	unsigned int down_rq;
	unsigned int up_rate;
	unsigned int down_rate;
	unsigned int cur_up_rate;
	unsigned int cur_down_rate;
	bool big_cpu;
	bool can_take_down;
	bool can_bring_up;
};

static DEFINE_PER_CPU(struct hotplug_cpuinfo, od_hotplug_cpuinfo);

static struct workqueue_struct *alucardhp_wq;

static struct delayed_work alucard_hotplug_work;

static struct hotplug_tuners {
	unsigned int hotplug_sampling_rate;
	unsigned int hotplug_enable;
	unsigned int min_cpus_online;
	unsigned int maxcoreslimit;
	unsigned int maxcoreslimit_sleep;
	unsigned int hp_io_is_busy;
	unsigned int min_little_load;
	unsigned int favor_big_cpus;
#ifdef CONFIG_THERMAL_NOTIFICATION
	unsigned int thermally_controlled;
#endif
#if defined(CONFIG_POWERSUSPEND)
	unsigned int hotplug_suspend;
	bool suspended;
	bool force_cpu_up;
#endif
	struct mutex alu_hotplug_mutex;
} hotplug_tuners_ins = {
	.hotplug_sampling_rate = 32,
	.hotplug_enable = 0,
	.min_cpus_online = 1,
	.maxcoreslimit = NR_CPUS,
	.maxcoreslimit_sleep = 1,
	.hp_io_is_busy = 0,
	.min_little_load = 64,
	.favor_big_cpus = 1,
#ifdef CONFIG_THERMAL_NOTIFICATION
	.thermally_controlled = 1,
#endif
#if defined(CONFIG_POWERSUSPEND)
	.hotplug_suspend = 1,
	.suspended = false,
	.force_cpu_up = false,
#endif
};

#define DOWN_INDEX		(0)
#define UP_INDEX		(1)

struct runqueue_data {
	unsigned int nr_run_avg;
	int64_t last_time;
	int64_t total_time;
	spinlock_t lock;
};

static struct runqueue_data *rq_data;

#ifdef CONFIG_THERMAL_NOTIFICATION
static struct notifier_block thermal_notif;
static long thermal_threshold;

static void update_cpu_available_to_bring_up_map(unsigned int max_core_limit, long thermal_threshold);

static int thermal_notifier_callback(struct notifier_block *this,
                                     unsigned long event, void *data)
{
        switch ((thermal_cpu_limits)event)
        {
		case THERMAL_EVENT_CPUS_WARMING:
                case THERMAL_EVENT_CPUS_HOT:
		case THERMAL_EVENT_CPUS_HOTTER:
		case THERMAL_EVENT_CPUS_HOTTEST:
		case THERMAL_EVENT_CPUS_LIMIT_HIT:
		case THERMAL_EVENT_CPUS_COLD:
		{
                        mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);
			thermal_threshold = event;
			if (hotplug_tuners_ins.thermally_controlled) {
				if (!hotplug_tuners_ins.suspended) {
					update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit, thermal_threshold);
				}
			}
                        mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
                        break;
		}
                default:
                        break;
        }
        return 0;
}
#endif

static void init_rq_avg_stats(void)
{
	rq_data->nr_run_avg = 0;
	rq_data->last_time = 0;
	rq_data->total_time = 0;
}

static int __init init_rq_avg(void)
{
	rq_data = kzalloc(sizeof(struct runqueue_data), GFP_KERNEL);
	if (rq_data == NULL) {
		pr_err("%s cannot allocate memory\n", __func__);
		return -ENOMEM;
	}
	spin_lock_init(&rq_data->lock);

	return 0;
}

static void exit_rq_avg(void)
{
	kfree(rq_data);
}

static unsigned int get_nr_run_avg(void)
{
	int64_t time_diff = 0;
	int64_t nr_run = 0;
	unsigned long flags = 0;
	int64_t cur_time;
	unsigned int nr_run_avg;

	cur_time = ktime_to_ns(ktime_get());

	spin_lock_irqsave(&rq_data->lock, flags);

	if (rq_data->last_time == 0)
		rq_data->last_time = cur_time;
	if (rq_data->nr_run_avg == 0)
		rq_data->total_time = 0;

	nr_run = nr_running() * 100;
	time_diff = cur_time - rq_data->last_time;
	do_div(time_diff, 1000 * 1000);

	if (time_diff != 0 && rq_data->total_time != 0) {
		nr_run = (nr_run * time_diff) +
			(rq_data->nr_run_avg * rq_data->total_time);
		do_div(nr_run, rq_data->total_time + time_diff);
	}
	rq_data->nr_run_avg = nr_run;
	rq_data->total_time += time_diff;
	rq_data->last_time = cur_time;

	nr_run_avg = rq_data->nr_run_avg;
	rq_data->nr_run_avg = 0;

	spin_unlock_irqrestore(&rq_data->lock, flags);

	return nr_run_avg;
}

typedef enum {IDLE, ON, OFF} HOTPLUG_STATUS;

typedef enum {LITTLE = 0, BIG = 1} CPU_TYPE;

#ifdef CONFIG_THERMAL_NOTIFICATION
static void update_cpu_available_to_bring_up_map(unsigned int max_core_limit, long thermal_threshold)
#else
static void update_cpu_available_to_bring_up_map(unsigned int max_core_limit)
#endif
{
        int i;
        struct hotplug_cpuinfo *pcpu_info;
        unsigned int cpus_to_mark_down = NR_CPUS - max_core_limit;
	unsigned int tdl = NR_CPUS/2 - 1;
	unsigned int tdb = NR_CPUS/2 - 1;
#ifdef CONFIG_THERMAL_NOTIFICATION
	unsigned int bcl, lcl;
#endif
	if ((max_core_limit <= 8) && (max_core_limit > 1)) {
		if (hotplug_tuners_ins.favor_big_cpus == 1) {
			tdl = (cpus_to_mark_down)/2 + cpus_to_mark_down%2;
			tdb = cpus_to_mark_down - tdl;
		}
		else {
			tdb = (cpus_to_mark_down)/2 + cpus_to_mark_down%2;
			tdl = cpus_to_mark_down - tdb;
		}
	}

	for (i = NR_CPUS-1; i > 0; i--) {
		pcpu_info = &per_cpu(od_hotplug_cpuinfo, i);
		pcpu_info->can_bring_up = true;
		if (pcpu_info->big_cpu) {
			if (tdb > 0) {
				pcpu_info->can_bring_up = false;
				tdb--;
				cpus_to_mark_down--;
			}
		}
		else if (tdl > 0) {
			pcpu_info->can_bring_up = false;
			tdl--;
			cpus_to_mark_down--;
		}
        }

#ifdef CONFIG_THERMAL_NOTIFICATION
	switch ((thermal_cpu_limits)thermal_threshold) {
		case THERMAL_EVENT_CPUS_WARMING:
		{
			bcl = 1;
			lcl = 0;
			break;
		}
		case THERMAL_EVENT_CPUS_HOT:
		{
			bcl = 1;
			lcl = 1;
			break;
		}
		case THERMAL_EVENT_CPUS_HOTTER:
		{
			bcl = 2;
			lcl = 1;
			break;
		}
		case THERMAL_EVENT_CPUS_HOTTEST:
		{
			bcl = 2;
			lcl = 2;
			break;
		}
		case THERMAL_EVENT_CPUS_LIMIT_HIT:
		{
			bcl = 3;
			lcl = 3;
			break;
		}
		default:
		{
			bcl = 0;
			lcl = 0;
		}
	}
	cpus_to_mark_down = bcl + lcl;
	for (i = NR_CPUS-1; (i > 0) && (cpus_to_mark_down > 0); i--) {
		pcpu_info = &per_cpu(od_hotplug_cpuinfo, i);
		if (pcpu_info->big_cpu) {
			if (bcl > 0) {
				pcpu_info->can_bring_up = false;
				bcl--;
				cpus_to_mark_down--;
			}
		}
		else if (lcl > 0) {
			pcpu_info->can_bring_up = false;
			lcl--;
			cpus_to_mark_down--;
		}
	}
#endif
}

static void update_cpu_available_to_take_down_map(unsigned int min_cpus_online)
{
	unsigned int i = 0;
	struct hotplug_cpuinfo *pcpu_info;
	unsigned int tdl = 1;
	unsigned int tdb = 0;

	if ((min_cpus_online > 1) && (min_cpus_online <= 8)) {
		if (hotplug_tuners_ins.favor_big_cpus == 1) {
			tdl = (min_cpus_online - 1)/2 + (min_cpus_online - 1)%2;
			tdb = min_cpus_online - tdl - 1;
		}
		else {
			tdl = min_cpus_online/2 + min_cpus_online%2;
			tdb = ((min_cpus_online - tdl) > 0) ? (min_cpus_online - tdl - 1) : (min_cpus_online - tdl);
		}
	}

	for (i = 1; i < NR_CPUS; i++) {
                pcpu_info = &per_cpu(od_hotplug_cpuinfo, i);
                pcpu_info->can_take_down = true;
                pcpu_info->cur_up_rate = 1;
                pcpu_info->cur_down_rate = 1;
		if (pcpu_info->big_cpu) {
                        if (tdb > 0) {
                                pcpu_info->can_take_down = false;
                                tdb--;
                        }
                }
                else {
                        if (tdl > 0) {
                                pcpu_info->can_take_down = false;
                                tdl--;
                        }
                }
        }
}

static unsigned int get_next_upcpu(unsigned int ccpu, int load, bool force_cpu_up)
{
        int i;
        struct hotplug_cpuinfo *pcpu_info;
        unsigned int upcpu = ccpu + 1;
	bool force_bring_up = force_cpu_up;

	if (upcpu >= NR_CPUS) {
		upcpu = 0;
	}
	else if (!force_bring_up) {
        	pcpu_info = &per_cpu(od_hotplug_cpuinfo, upcpu);
		force_bring_up = !pcpu_info->can_take_down && cpu_is_offline(upcpu);	
        	while (!force_bring_up && !pcpu_info->can_bring_up && (upcpu < NR_CPUS)) {
                	upcpu++;
			if (upcpu < NR_CPUS) {
				pcpu_info = &per_cpu(od_hotplug_cpuinfo, upcpu);
				force_bring_up = !pcpu_info->can_take_down && cpu_is_offline(upcpu);
			}
        	}

        	if (upcpu >= NR_CPUS) {
                	upcpu = 0;
        	}
		else if (!force_bring_up) {
        		if (load < hotplug_tuners_ins.min_little_load) {
                		for (i = 4; i < NR_CPUS; i++) {
                        		pcpu_info = &per_cpu(od_hotplug_cpuinfo, i);
                        		if (pcpu_info->can_bring_up && cpu_is_offline(i)) {
                                    		upcpu = i;
                                		break;
					}
                        	}
                	}
        	}
	}

        return upcpu;
}

static void __ref hotplug_work_fn(struct work_struct *work)
{
	unsigned int upmaxcoreslimit = 0;
	unsigned int min_cpus_online;
	unsigned int cpu = 0;
	int online_cpu = 0;
	int offline_cpu = 0;
	int online_cpus = 0;
	unsigned int rq_avg;
	bool force_up = false;
	HOTPLUG_STATUS hotplug_onoff[NR_CPUS] = {IDLE, IDLE, IDLE, IDLE, IDLE, IDLE, IDLE, IDLE};
	int delay;
	int io_busy;

	if (!mutex_trylock(&hotplug_tuners_ins.alu_hotplug_mutex)) {
		queue_delayed_work_on(0, alucardhp_wq, &alucard_hotplug_work, 32);
		return;
	}

	min_cpus_online = hotplug_tuners_ins.min_cpus_online;

	io_busy = hotplug_tuners_ins.hp_io_is_busy;

#if defined(CONFIG_POWERSUSPEND)
        force_up = hotplug_tuners_ins.force_cpu_up;
#endif

	rq_avg = get_nr_run_avg();

#if defined(CONFIG_POWERSUSPEND)
	if (hotplug_tuners_ins.suspended)
		upmaxcoreslimit = hotplug_tuners_ins.maxcoreslimit_sleep;
	else
#endif
		upmaxcoreslimit = hotplug_tuners_ins.maxcoreslimit;

	get_online_cpus();

	online_cpus = num_online_cpus();

	for_each_online_cpu(cpu) {
		struct hotplug_cpuinfo *pcpu_info = &per_cpu(od_hotplug_cpuinfo, cpu);
		unsigned int upcpu = 0;
#ifndef CONFIG_ALUCARD_HOTPLUG_USE_CPU_UTIL
		u64 cur_wall_time, cur_idle_time;
		unsigned int wall_time, idle_time;
#endif
		int cur_load = -1;
		unsigned int cur_freq = 0;
		bool check_up = false, check_down = false;

#ifdef CONFIG_ALUCARD_HOTPLUG_USE_CPU_UTIL
		cur_load = cpufreq_quick_get_util(cpu);
#else
		cur_idle_time = get_cpu_idle_time(cpu, &cur_wall_time, io_busy);

		wall_time = (unsigned int)
				(cur_wall_time -
					pcpu_info->prev_cpu_wall);
		pcpu_info->prev_cpu_wall = cur_wall_time;

		idle_time = (unsigned int)
				(cur_idle_time -
					pcpu_info->prev_cpu_idle);
		pcpu_info->prev_cpu_idle = cur_idle_time;

		/* if wall_time < idle_time, evaluate cpu load next time */
		if (wall_time >= idle_time) {
			/*
			 * if wall_time is equal to idle_time,
			 * cpu_load is equal to 0
			 */
			cur_load = wall_time > idle_time ? (100 *
				(wall_time - idle_time)) / wall_time : 0;
		}
#endif

		upcpu = get_next_upcpu(cpu, cur_load, force_up);

		/* if cur_load < 0, evaluate cpu load next time */
		if (cur_load >= 0) {
			/* get the cpu current frequency */
			/* cur_freq = acpuclk_get_rate(cpu); */
			cur_freq = cpufreq_quick_get(cpu);

			if (pcpu_info->cur_up_rate > pcpu_info->up_rate)
				pcpu_info->cur_up_rate = 1;

			if (pcpu_info->cur_down_rate > pcpu_info->down_rate)
				pcpu_info->cur_down_rate = 1;

			check_up = (pcpu_info->cur_up_rate % pcpu_info->up_rate == 0);
			check_down = (pcpu_info->cur_down_rate % pcpu_info->down_rate == 0);

			if ((cpu > 0) &&
			    (((online_cpus - offline_cpu) > upmaxcoreslimit)) &&
                             (pcpu_info->can_take_down || !pcpu_info->can_bring_up)) {
					hotplug_onoff[cpu] = OFF;
					pcpu_info->cur_up_rate = 1;
					pcpu_info->cur_down_rate = 1;
					++offline_cpu;
					continue;
#if defined(CONFIG_POWERSUSPEND)
			} else if (force_up == true || (online_cpus + online_cpu) < min_cpus_online) {
#else
			} else if ((online_cpus + online_cpu) < min_cpus_online) {
#endif
					if (upcpu > 0) {
						if (!cpu_online(upcpu)) {
							hotplug_onoff[upcpu] = ON;
							pcpu_info->cur_up_rate = 1;
							pcpu_info->cur_down_rate = 1;
							++online_cpu;
						}
					}
					continue;
			}

			if ((upcpu > 0) &&
			    (!cpu_online(upcpu)) &&
			    ((online_cpus + online_cpu) < upmaxcoreslimit) &&
 			    (cur_load >= pcpu_info->up_load) &&
			    (cur_freq >= pcpu_info->up_freq) &&
			    (rq_avg > pcpu_info->up_rq)) {
				++pcpu_info->cur_up_rate;
				if (check_up) {
					hotplug_onoff[upcpu] = ON;
					pcpu_info->cur_up_rate = 1;
					pcpu_info->cur_down_rate = 1;
					++online_cpu;
				}
			} else if (pcpu_info->can_take_down &&
				   (cur_load < pcpu_info->down_load ||
				   (cur_freq <= pcpu_info->down_freq &&
				   rq_avg <= pcpu_info->down_rq))) {
					++pcpu_info->cur_down_rate;
					if (check_down) {
						hotplug_onoff[cpu] = OFF;
						pcpu_info->cur_up_rate = 1;
						pcpu_info->cur_down_rate = 1;
						++offline_cpu;
					}
			} else {
				pcpu_info->cur_up_rate = 1;
				pcpu_info->cur_down_rate = 1;
			}
		}
	}
	put_online_cpus();

	for (cpu = 1; cpu < NR_CPUS; cpu++) {
		if (hotplug_onoff[cpu] == ON) {
			cpu_up(cpu);
		}
		else if (hotplug_onoff[cpu] == OFF) {
			cpu_down(cpu);
		}
	}

#if defined(CONFIG_POWERSUSPEND)
	if (force_up == true)
		hotplug_tuners_ins.force_cpu_up = false;
#endif

	delay = msecs_to_jiffies(hotplug_tuners_ins.hotplug_sampling_rate);

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);

	queue_delayed_work_on(0, alucardhp_wq, &alucard_hotplug_work, delay);
}

#ifdef CONFIG_POWERSUSPEND
static void __ref alucard_hotplug_suspend(struct power_suspend *handler)
{
	if (hotplug_tuners_ins.hotplug_enable > 0
		&& hotplug_tuners_ins.hotplug_suspend == 1) { 
			mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);
			hotplug_tuners_ins.suspended = true;
#ifdef CONFIG_THERMAL_NOTIFICATION
			update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit_sleep, THERMAL_EVENT_CPUS_COLD);
#else
			update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit_sleep);
#endif
			mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
	}
}

static void __ref alucard_hotplug_resume(struct power_suspend *handler)
{
	if (hotplug_tuners_ins.hotplug_enable > 0
		&& hotplug_tuners_ins.hotplug_suspend == 1) {
			mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);
			hotplug_tuners_ins.suspended = false;
			// wake up everyone
			hotplug_tuners_ins.force_cpu_up = true;
#ifdef CONFIG_THERMAL_NOTIFICATION
			update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit, thermal_threshold);
#else
			update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit);
#endif
			mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
	}
}

static struct power_suspend alucard_hotplug_power_suspend_driver = {
	.suspend = alucard_hotplug_suspend,
	.resume = alucard_hotplug_resume,
};
#endif  // CONFIG_POWERSUSPEND

static int hotplug_start(void)
{
	unsigned int cpu;
	int ret = 0;

	alucardhp_wq = alloc_workqueue("alucardhp_wq", WQ_HIGHPRI, 0);

	if (!alucardhp_wq) {
		printk(KERN_ERR "Failed to create alucard hotplug workqueue\n");
		return -EFAULT;
	}

	ret = init_rq_avg();
	if (ret) {
		destroy_workqueue(alucardhp_wq);
		return ret;
	}

#if defined(CONFIG_POWERSUSPEND)
	hotplug_tuners_ins.suspended = false;
	hotplug_tuners_ins.force_cpu_up = false;
#endif

	update_cpu_available_to_take_down_map(hotplug_tuners_ins.min_cpus_online);
#ifdef CONFIG_THERMAL_NOTIFICATION
	update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit, thermal_threshold);
#else
	update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit);
#endif
	

	get_online_cpus();
	for_each_possible_cpu(cpu) {
		struct hotplug_cpuinfo *pcpu_info = &per_cpu(od_hotplug_cpuinfo, cpu);

#ifndef CONFIG_ALUCARD_HOTPLUG_USE_CPU_UTIL
		pcpu_info->prev_cpu_idle = get_cpu_idle_time(cpu,
				&pcpu_info->prev_cpu_wall, hotplug_tuners_ins.hp_io_is_busy);
#endif
		pcpu_info->cur_up_rate = 1;
		pcpu_info->cur_down_rate = 1;
	}
	put_online_cpus();

	init_rq_avg_stats();
	INIT_DELAYED_WORK(&alucard_hotplug_work, hotplug_work_fn);
	queue_delayed_work_on(0, alucardhp_wq, &alucard_hotplug_work,
						msecs_to_jiffies(hotplug_tuners_ins.hotplug_sampling_rate));

#if defined(CONFIG_POWERSUSPEND)
	register_power_suspend(&alucard_hotplug_power_suspend_driver);
#endif  // CONFIG_POWERSUSPEND

#ifdef CONFIG_THERMAL_NOTIFICATION
	if (thermal_register_client(&thermal_notif) != 0) {
                pr_err("%s: Failed to register thermal callback\n", __func__);
        }
#endif

	return 0;
}

static void hotplug_stop(void)
{
	unsigned int cpu;
	HOTPLUG_STATUS hotplug_onoff[NR_CPUS] = {IDLE, IDLE, IDLE, IDLE, IDLE, IDLE, IDLE, IDLE};
	
#if defined(CONFIG_POWERSUSPEND)
	unregister_power_suspend(&alucard_hotplug_power_suspend_driver);
#endif  // CONFIG_POWERSUSPEND

#ifdef CONFIG_THERMAL_NOTIFICATION
        if (thermal_unregister_client(&thermal_notif) != 0) {
                pr_err("%s: Failed to unregister thermal callback\n", __func__);
        }
	thermal_threshold = THERMAL_EVENT_CPUS_COLD;
#endif
	cancel_delayed_work_sync(&alucard_hotplug_work);

	exit_rq_avg();

	destroy_workqueue(alucardhp_wq);

	get_online_cpus();
	for_each_possible_cpu(cpu) {
		if (cpu_is_offline(cpu)) {
			hotplug_onoff[cpu] = OFF;
		}
		else {
			hotplug_onoff[cpu] = ON;
		}
	}
	put_online_cpus();

	for (cpu = 1; cpu < NR_CPUS; cpu++) {
		if (hotplug_onoff[cpu] == OFF) {
			cpu_up(cpu);
		}
	}
}

#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct kobj_attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%d\n", \
			hotplug_tuners_ins.object);			\
}

show_one(hotplug_sampling_rate, hotplug_sampling_rate);
show_one(hotplug_enable, hotplug_enable);
show_one(min_cpus_online, min_cpus_online);
show_one(maxcoreslimit, maxcoreslimit);
show_one(maxcoreslimit_sleep, maxcoreslimit_sleep);
show_one(hp_io_is_busy, hp_io_is_busy);
show_one(min_little_load, min_little_load);
show_one(favor_big_cpus, favor_big_cpus);
#ifdef CONFIG_THERMAL_NOTIFICATION
show_one(thermally_controlled, thermally_controlled)
#endif
#if defined(CONFIG_POWERSUSPEND)
show_one(hotplug_suspend, hotplug_suspend);
#endif

#define show_pcpu_param(file_name, var_name, num_core)		\
static ssize_t show_##file_name		\
(struct kobject *kobj, struct kobj_attribute *attr, char *buf)		\
{									\
	struct hotplug_cpuinfo *pcpu_info = &per_cpu(od_hotplug_cpuinfo, num_core - 1); \
	return sprintf(buf, "%u\n", \
			pcpu_info->var_name);		\
}

show_pcpu_param(hotplug_freq_1_1, up_freq, 1);
show_pcpu_param(hotplug_freq_2_1, up_freq, 2);
show_pcpu_param(hotplug_freq_3_1, up_freq, 3);
show_pcpu_param(hotplug_freq_4_1, up_freq, 4);
show_pcpu_param(hotplug_freq_5_1, up_freq, 5);
show_pcpu_param(hotplug_freq_6_1, up_freq, 6);
show_pcpu_param(hotplug_freq_7_1, up_freq, 7);
show_pcpu_param(hotplug_freq_8_1, up_freq, 8);
show_pcpu_param(hotplug_freq_2_0, down_freq, 2);
show_pcpu_param(hotplug_freq_3_0, down_freq, 3);
show_pcpu_param(hotplug_freq_4_0, down_freq, 4);
show_pcpu_param(hotplug_freq_5_0, down_freq, 5);
show_pcpu_param(hotplug_freq_6_0, down_freq, 6);
show_pcpu_param(hotplug_freq_7_0, down_freq, 7);
show_pcpu_param(hotplug_freq_8_0, down_freq, 8);

show_pcpu_param(hotplug_load_1_1, up_load, 1);
show_pcpu_param(hotplug_load_2_1, up_load, 2);
show_pcpu_param(hotplug_load_3_1, up_load, 3);
show_pcpu_param(hotplug_load_4_1, up_load, 4);
show_pcpu_param(hotplug_load_5_1, up_load, 5);
show_pcpu_param(hotplug_load_6_1, up_load, 6);
show_pcpu_param(hotplug_load_7_1, up_load, 7);
show_pcpu_param(hotplug_load_8_1, up_load, 8);
show_pcpu_param(hotplug_load_2_0, down_load, 2);
show_pcpu_param(hotplug_load_3_0, down_load, 3);
show_pcpu_param(hotplug_load_4_0, down_load, 4);
show_pcpu_param(hotplug_load_5_0, down_load, 5);
show_pcpu_param(hotplug_load_6_0, down_load, 6);
show_pcpu_param(hotplug_load_7_0, down_load, 7);
show_pcpu_param(hotplug_load_8_0, down_load, 8);

show_pcpu_param(hotplug_rq_1_1, up_rq, 1);
show_pcpu_param(hotplug_rq_2_1, up_rq, 2);
show_pcpu_param(hotplug_rq_3_1, up_rq, 3);
show_pcpu_param(hotplug_rq_4_1, up_rq, 4);
show_pcpu_param(hotplug_rq_5_1, up_rq, 5);
show_pcpu_param(hotplug_rq_6_1, up_rq, 6);
show_pcpu_param(hotplug_rq_7_1, up_rq, 7);
show_pcpu_param(hotplug_rq_8_1, up_rq, 8);
show_pcpu_param(hotplug_rq_2_0, down_rq, 2);
show_pcpu_param(hotplug_rq_3_0, down_rq, 3);
show_pcpu_param(hotplug_rq_4_0, down_rq, 4);
show_pcpu_param(hotplug_rq_5_0, down_rq, 5);
show_pcpu_param(hotplug_rq_6_0, down_rq, 6);
show_pcpu_param(hotplug_rq_7_0, down_rq, 7);
show_pcpu_param(hotplug_rq_8_0, down_rq, 8);

show_pcpu_param(hotplug_rate_1_1, up_rate, 1);
show_pcpu_param(hotplug_rate_2_1, up_rate, 2);
show_pcpu_param(hotplug_rate_3_1, up_rate, 3);
show_pcpu_param(hotplug_rate_4_1, up_rate, 4);
show_pcpu_param(hotplug_rate_5_1, up_rate, 5);
show_pcpu_param(hotplug_rate_6_1, up_rate, 6);
show_pcpu_param(hotplug_rate_7_1, up_rate, 7);
show_pcpu_param(hotplug_rate_8_1, up_rate, 8);
show_pcpu_param(hotplug_rate_2_0, down_rate, 2);
show_pcpu_param(hotplug_rate_3_0, down_rate, 3);
show_pcpu_param(hotplug_rate_4_0, down_rate, 4);
show_pcpu_param(hotplug_rate_5_0, down_rate, 5);
show_pcpu_param(hotplug_rate_6_0, down_rate, 6);
show_pcpu_param(hotplug_rate_7_0, down_rate, 7);
show_pcpu_param(hotplug_rate_8_0, down_rate, 8);

#define store_pcpu_param(file_name, var_name, num_core)		\
static ssize_t store_##file_name				\
(struct kobject *kobj, struct kobj_attribute *attr,		\
	const char *buf, size_t count)				\
{								\
	unsigned int input;					\
	struct hotplug_cpuinfo *pcpu_info; 			\
	int ret;						\
								\
	ret = sscanf(buf, "%u", &input);			\
	if (ret != 1)						\
		return -EINVAL;					\
								\
	pcpu_info = &per_cpu(od_hotplug_cpuinfo, num_core - 1);	\
								\
	if (input == pcpu_info->var_name) {			\
		return count;					\
	}							\
								\
	pcpu_info->var_name = input;				\
	return count;						\
}

store_pcpu_param(hotplug_freq_1_1, up_freq, 1);
store_pcpu_param(hotplug_freq_2_1, up_freq, 2);
store_pcpu_param(hotplug_freq_3_1, up_freq, 3);
store_pcpu_param(hotplug_freq_4_1, up_freq, 4);
store_pcpu_param(hotplug_freq_5_1, up_freq, 5);
store_pcpu_param(hotplug_freq_6_1, up_freq, 6);
store_pcpu_param(hotplug_freq_7_1, up_freq, 7);
store_pcpu_param(hotplug_freq_8_1, up_freq, 8);
store_pcpu_param(hotplug_freq_2_0, down_freq, 2);
store_pcpu_param(hotplug_freq_3_0, down_freq, 3);
store_pcpu_param(hotplug_freq_4_0, down_freq, 4);
store_pcpu_param(hotplug_freq_5_0, down_freq, 5);
store_pcpu_param(hotplug_freq_6_0, down_freq, 6);
store_pcpu_param(hotplug_freq_7_0, down_freq, 7);
store_pcpu_param(hotplug_freq_8_0, down_freq, 8);

store_pcpu_param(hotplug_load_1_1, up_load, 1);
store_pcpu_param(hotplug_load_2_1, up_load, 2);
store_pcpu_param(hotplug_load_3_1, up_load, 3);
store_pcpu_param(hotplug_load_4_1, up_load, 4);
store_pcpu_param(hotplug_load_5_1, up_load, 5);
store_pcpu_param(hotplug_load_6_1, up_load, 6);
store_pcpu_param(hotplug_load_7_1, up_load, 7);
store_pcpu_param(hotplug_load_8_1, up_load, 8);
store_pcpu_param(hotplug_load_2_0, down_load, 2);
store_pcpu_param(hotplug_load_3_0, down_load, 3);
store_pcpu_param(hotplug_load_4_0, down_load, 4);
store_pcpu_param(hotplug_load_5_0, down_load, 5);
store_pcpu_param(hotplug_load_6_0, down_load, 6);
store_pcpu_param(hotplug_load_7_0, down_load, 7);
store_pcpu_param(hotplug_load_8_0, down_load, 8);

store_pcpu_param(hotplug_rq_1_1, up_rq, 1);
store_pcpu_param(hotplug_rq_2_1, up_rq, 2);
store_pcpu_param(hotplug_rq_3_1, up_rq, 3);
store_pcpu_param(hotplug_rq_4_1, up_rq, 4);
store_pcpu_param(hotplug_rq_5_1, up_rq, 5);
store_pcpu_param(hotplug_rq_6_1, up_rq, 6);
store_pcpu_param(hotplug_rq_7_1, up_rq, 7);
store_pcpu_param(hotplug_rq_8_1, up_rq, 8);
store_pcpu_param(hotplug_rq_2_0, down_rq, 2);
store_pcpu_param(hotplug_rq_3_0, down_rq, 3);
store_pcpu_param(hotplug_rq_4_0, down_rq, 4);
store_pcpu_param(hotplug_rq_5_0, down_rq, 5);
store_pcpu_param(hotplug_rq_6_0, down_rq, 6);
store_pcpu_param(hotplug_rq_7_0, down_rq, 7);
store_pcpu_param(hotplug_rq_8_0, down_rq, 8);

store_pcpu_param(hotplug_rate_1_1, up_rate, 1);
store_pcpu_param(hotplug_rate_2_1, up_rate, 2);
store_pcpu_param(hotplug_rate_3_1, up_rate, 3);
store_pcpu_param(hotplug_rate_4_1, up_rate, 4);
store_pcpu_param(hotplug_rate_5_1, up_rate, 5);
store_pcpu_param(hotplug_rate_6_1, up_rate, 6);
store_pcpu_param(hotplug_rate_7_1, up_rate, 7);
store_pcpu_param(hotplug_rate_8_1, up_rate, 8);
store_pcpu_param(hotplug_rate_2_0, down_rate, 2);
store_pcpu_param(hotplug_rate_3_0, down_rate, 3);
store_pcpu_param(hotplug_rate_4_0, down_rate, 4);
store_pcpu_param(hotplug_rate_5_0, down_rate, 5);
store_pcpu_param(hotplug_rate_6_0, down_rate, 6);
store_pcpu_param(hotplug_rate_7_0, down_rate, 7);
store_pcpu_param(hotplug_rate_8_0, down_rate, 8);

define_one_global_rw(hotplug_freq_1_1);
define_one_global_rw(hotplug_freq_2_0);
define_one_global_rw(hotplug_freq_2_1);
define_one_global_rw(hotplug_freq_3_0);
define_one_global_rw(hotplug_freq_3_1);
define_one_global_rw(hotplug_freq_4_0);
define_one_global_rw(hotplug_freq_4_1);
define_one_global_rw(hotplug_freq_5_0);
define_one_global_rw(hotplug_freq_5_1);
define_one_global_rw(hotplug_freq_6_0);
define_one_global_rw(hotplug_freq_6_1);
define_one_global_rw(hotplug_freq_7_0);
define_one_global_rw(hotplug_freq_7_1);
define_one_global_rw(hotplug_freq_8_0);
define_one_global_rw(hotplug_freq_8_1);

define_one_global_rw(hotplug_load_1_1);
define_one_global_rw(hotplug_load_2_0);
define_one_global_rw(hotplug_load_2_1);
define_one_global_rw(hotplug_load_3_0);
define_one_global_rw(hotplug_load_3_1);
define_one_global_rw(hotplug_load_4_0);
define_one_global_rw(hotplug_load_4_1);
define_one_global_rw(hotplug_load_5_0);
define_one_global_rw(hotplug_load_5_1);
define_one_global_rw(hotplug_load_6_0);
define_one_global_rw(hotplug_load_6_1);
define_one_global_rw(hotplug_load_7_0);
define_one_global_rw(hotplug_load_7_1);
define_one_global_rw(hotplug_load_8_0);
define_one_global_rw(hotplug_load_8_1);

define_one_global_rw(hotplug_rq_1_1);
define_one_global_rw(hotplug_rq_2_0);
define_one_global_rw(hotplug_rq_2_1);
define_one_global_rw(hotplug_rq_3_0);
define_one_global_rw(hotplug_rq_3_1);
define_one_global_rw(hotplug_rq_4_0);
define_one_global_rw(hotplug_rq_4_1);
define_one_global_rw(hotplug_rq_5_0);
define_one_global_rw(hotplug_rq_5_1);
define_one_global_rw(hotplug_rq_6_0);
define_one_global_rw(hotplug_rq_6_1);
define_one_global_rw(hotplug_rq_7_0);
define_one_global_rw(hotplug_rq_7_1);
define_one_global_rw(hotplug_rq_8_0);
define_one_global_rw(hotplug_rq_8_1);

define_one_global_rw(hotplug_rate_1_1);
define_one_global_rw(hotplug_rate_2_0);
define_one_global_rw(hotplug_rate_2_1);
define_one_global_rw(hotplug_rate_3_0);
define_one_global_rw(hotplug_rate_3_1);
define_one_global_rw(hotplug_rate_4_0);
define_one_global_rw(hotplug_rate_4_1);
define_one_global_rw(hotplug_rate_5_0);
define_one_global_rw(hotplug_rate_5_1);
define_one_global_rw(hotplug_rate_6_0);
define_one_global_rw(hotplug_rate_6_1);
define_one_global_rw(hotplug_rate_7_0);
define_one_global_rw(hotplug_rate_7_1);
define_one_global_rw(hotplug_rate_8_0);
define_one_global_rw(hotplug_rate_8_1);

static void cpus_hotplugging(int status) {
	int ret = 0;

	if (status) {
		ret = hotplug_start();
		if (ret)
			status = 0;
	} else {
		hotplug_stop();
	}

	hotplug_tuners_ins.hotplug_enable = status;
}

/* hotplug_sampling_rate */
static ssize_t store_hotplug_sampling_rate(struct kobject *a,
				struct kobj_attribute *b,
				const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(input, 10);

	mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

	if (input == hotplug_tuners_ins.hotplug_sampling_rate) {
		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
		return count;
	}

	hotplug_tuners_ins.hotplug_sampling_rate = input;

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);

	return count;
}

/* hotplug_enable */
static ssize_t store_hotplug_enable(struct kobject *a, struct kobj_attribute *b,
				  const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	input = input > 0;

	mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

	if (hotplug_tuners_ins.hotplug_enable == input) {
		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
		return count;
	}

	if (input > 0)
		cpus_hotplugging(1);
	else
		cpus_hotplugging(0);

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);

	return count;
}

/* min_cpus_online */
static ssize_t store_min_cpus_online(struct kobject *a, struct kobj_attribute *b,
				  const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(input > NR_CPUS ? NR_CPUS : input, 1);

	mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

	if (hotplug_tuners_ins.min_cpus_online == input) {
		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
		return count;
	}

	hotplug_tuners_ins.min_cpus_online = input;

	update_cpu_available_to_take_down_map(hotplug_tuners_ins.min_cpus_online);

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);

	return count;
}

/* maxcoreslimit */
static ssize_t store_maxcoreslimit(struct kobject *a, struct kobj_attribute *b,
				  const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(input > NR_CPUS ? NR_CPUS : input, 1);

	mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

	if ((hotplug_tuners_ins.maxcoreslimit == input) || (input < hotplug_tuners_ins.min_cpus_online)) {
		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
		return count;
	}

	hotplug_tuners_ins.maxcoreslimit = input;

#ifdef CONFIG_THERMAL_NOTIFICATION
	update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit, thermal_threshold);
#else
	update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit);
#endif

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);

	return count;
}

/* maxcoreslimit_sleep */
static ssize_t store_maxcoreslimit_sleep(struct kobject *a,
				struct kobj_attribute *b,
				const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(input > NR_CPUS ? NR_CPUS : input, 1);

	mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

	if ((hotplug_tuners_ins.maxcoreslimit_sleep == input) || (input < hotplug_tuners_ins.min_cpus_online)) {
		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
		return count;
	}

	hotplug_tuners_ins.maxcoreslimit_sleep = input;

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);

	return count;
}

/* hp_io_is_busy */
static ssize_t store_hp_io_is_busy(struct kobject *a, struct kobj_attribute *b,
				   const char *buf, size_t count)
{
	unsigned int input, j;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input > 1)
		input = 1;

	mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

	if (input == hotplug_tuners_ins.hp_io_is_busy) {
		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
		return count;
	}

	hotplug_tuners_ins.hp_io_is_busy = !!input;
#ifndef CONFIG_ALUCARD_HOTPLUG_USE_CPU_UTIL
	/* we need to re-evaluate prev_cpu_idle */
	if (hotplug_tuners_ins.hotplug_enable > 0) {
		for_each_online_cpu(j) {
			struct hotplug_cpuinfo *pcpu_info = &per_cpu(od_hotplug_cpuinfo, j);
			pcpu_info->prev_cpu_idle = get_cpu_idle_time(j,
					&pcpu_info->prev_cpu_wall, hotplug_tuners_ins.hp_io_is_busy);
		}
	}
#endif

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
	return count;
}

/* min_little_load */
static ssize_t store_min_little_load(struct kobject *a, struct kobj_attribute *b,
                                     const char *buf, size_t count)
{
        int input;
        int ret;

        ret = sscanf(buf, "%u", &input);
        if (ret != 1)
                return -EINVAL;

	if ((input > 0) && (input <= 100)) {
		mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

        	if (input == hotplug_tuners_ins.min_little_load) {
			mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
                	return count;
        	}

        	hotplug_tuners_ins.min_little_load = input;

		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
	}

        return count;
}

/* favor_big_cpus */
static ssize_t store_favor_big_cpus(struct kobject *a, struct kobj_attribute *b,
                                    const char *buf, size_t count)
{
        int input;
        int ret;

        ret = sscanf(buf, "%u", &input);
        if (ret != 1)
                return -EINVAL;

        if ((input > 0) && (input <= 1)) {
                mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

                if (input == hotplug_tuners_ins.favor_big_cpus) {
                        mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
                        return count;
                }

                hotplug_tuners_ins.favor_big_cpus = input;

		update_cpu_available_to_take_down_map(hotplug_tuners_ins.min_cpus_online);

                mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
        }

        return count;
}

#ifdef CONFIG_THERMAL_NOTIFICATION
/* thermally_controlled */
static ssize_t store_thermally_controlled(struct kobject *a, struct kobj_attribute *b,
                                          const char *buf, size_t count)
{
        int input;
        int ret;

        ret = sscanf(buf, "%u", &input);
        if (ret != 1)
                return -EINVAL;

        if ((input > 0) && (input <= 1)) {
                mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);
                if (input == hotplug_tuners_ins.thermally_controlled) {
                        mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
                        return count;
                }

                hotplug_tuners_ins.thermally_controlled = input;
		if (hotplug_tuners_ins.thermally_controlled == 0) {
			thermal_threshold = THERMAL_EVENT_CPUS_COLD;
		}
		update_cpu_available_to_bring_up_map(hotplug_tuners_ins.maxcoreslimit, thermal_threshold);
                mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
        }

        return count;
}
#endif

/*
 * hotplug_suspend control
 * if set = 1 hotplug will sleep,
 * if set = 0, then hoplug will be active all the time.
 */
#if defined(CONFIG_POWERSUSPEND)
static ssize_t store_hotplug_suspend(struct kobject *a,
				     struct kobj_attribute *b,
				     const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	input = input > 0;

	mutex_lock(&hotplug_tuners_ins.alu_hotplug_mutex);

	if (hotplug_tuners_ins.hotplug_suspend == input) {
		mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);
		return count;
	}

	if (input > 0)
		hotplug_tuners_ins.hotplug_suspend = 1;
	else {
		hotplug_tuners_ins.hotplug_suspend = 0;
		hotplug_tuners_ins.suspended = false;
	}

	mutex_unlock(&hotplug_tuners_ins.alu_hotplug_mutex);

	return count;
}
#endif

define_one_global_rw(hotplug_sampling_rate);
define_one_global_rw(hotplug_enable);
define_one_global_rw(min_cpus_online);
define_one_global_rw(maxcoreslimit);
define_one_global_rw(maxcoreslimit_sleep);
define_one_global_rw(hp_io_is_busy);
define_one_global_rw(min_little_load);
define_one_global_rw(favor_big_cpus);
#ifdef CONFIG_THERMAL_NOTIFICATION
define_one_global_rw(thermally_controlled);
#endif
#if defined(CONFIG_POWERSUSPEND)
define_one_global_rw(hotplug_suspend);
#endif

static struct attribute *alucard_hotplug_attributes[] = {
	&hotplug_sampling_rate.attr,
	&hotplug_enable.attr,
	&hotplug_freq_1_1.attr,
        &hotplug_freq_2_0.attr,
        &hotplug_freq_2_1.attr,
        &hotplug_freq_3_0.attr,
        &hotplug_freq_3_1.attr,
        &hotplug_freq_4_0.attr,
        &hotplug_freq_4_1.attr,
        &hotplug_freq_5_0.attr,
        &hotplug_freq_5_1.attr,
        &hotplug_freq_6_0.attr,
        &hotplug_freq_6_1.attr,
        &hotplug_freq_7_0.attr,
        &hotplug_freq_7_1.attr,
        &hotplug_freq_8_0.attr,
        &hotplug_freq_8_1.attr,
        &hotplug_load_1_1.attr,
        &hotplug_load_2_0.attr,
        &hotplug_load_2_1.attr,
        &hotplug_load_3_0.attr,
        &hotplug_load_3_1.attr,
        &hotplug_load_4_0.attr,
        &hotplug_load_4_1.attr,
        &hotplug_load_5_0.attr,
        &hotplug_load_5_1.attr,
        &hotplug_load_6_0.attr,
        &hotplug_load_6_1.attr,
        &hotplug_load_7_0.attr,
        &hotplug_load_7_1.attr,
        &hotplug_load_8_0.attr,
        &hotplug_load_8_1.attr,
	&hotplug_rq_1_1.attr,
        &hotplug_rq_2_0.attr,
        &hotplug_rq_2_1.attr,
        &hotplug_rq_3_0.attr,
        &hotplug_rq_3_1.attr,
        &hotplug_rq_4_0.attr,
        &hotplug_rq_4_1.attr,
        &hotplug_rq_5_0.attr,
        &hotplug_rq_5_1.attr,
        &hotplug_rq_6_0.attr,
        &hotplug_rq_6_1.attr,
        &hotplug_rq_7_0.attr,
        &hotplug_rq_7_1.attr,
        &hotplug_rq_8_0.attr,
        &hotplug_rq_8_1.attr,
        &hotplug_rate_1_1.attr,
        &hotplug_rate_2_0.attr,
        &hotplug_rate_2_1.attr,
        &hotplug_rate_3_0.attr,
        &hotplug_rate_3_1.attr,
        &hotplug_rate_4_0.attr,
        &hotplug_rate_4_1.attr,
        &hotplug_rate_5_0.attr,
        &hotplug_rate_5_1.attr,
        &hotplug_rate_6_0.attr,
        &hotplug_rate_6_1.attr,
        &hotplug_rate_7_0.attr,
        &hotplug_rate_7_1.attr,
        &hotplug_rate_8_0.attr,
        &hotplug_rate_8_1.attr,
        &min_cpus_online.attr,
        &maxcoreslimit.attr,
        &maxcoreslimit_sleep.attr,
        &hp_io_is_busy.attr,
        &min_little_load.attr,
	&favor_big_cpus.attr,
#ifdef CONFIG_THERMAL_NOTIFICATION
	&thermally_controlled.attr,
#endif
#if defined(CONFIG_POWERSUSPEND)
	&hotplug_suspend.attr,
#endif
	NULL
};

static struct attribute_group alucard_hotplug_attr_group = {
	.attrs = alucard_hotplug_attributes,
	.name = "alucard_hotplug",
};

static int __init alucard_hotplug_init(void)
{
	int ret;
	unsigned int cpu;
	unsigned int hotplug_freq[NR_CPUS][2] = {
		{0, 787200},
                {1113600, 1516800},
                {1344000, 1670400},
                {1516800, 1881600},
                {0, 614400},
                {883200, 1094400},
                {1094400, 1382400},
                {1382400, 1536000}
	};
	unsigned int hotplug_load[NR_CPUS][2] = {
		{0, 60},
                {45, 65},
                {55, 75},
                {65, 0},
                {0, 45},
                {35, 55},
                {45, 65},
                {55, 0}
	};
	unsigned int hotplug_rq[NR_CPUS][2] = {
		{0, 100},
                {200, 400},
                {300, 500},
                {500, 0},
                {0, 100},
                {200, 300},
                {300, 400},
                {400, 0}
	};
	unsigned int hotplug_rate[NR_CPUS][2] = {
		{1, 1},
                {4, 2},
                {3, 3},
                {2, 4},
                {1, 1},
                {4, 1},
                {3, 1},
                {2, 1}
	};

	bool hotplug_initstate[NR_CPUS] = {false, false, false, false, false, false, false, false};
	unsigned int hotplug_cputype[NR_CPUS] = {BIG, BIG, BIG, BIG, LITTLE, LITTLE, LITTLE, LITTLE};

	ret = sysfs_create_group(kernel_kobj, &alucard_hotplug_attr_group);
	if (ret) {
		printk(KERN_ERR "failed at(%d)\n", __LINE__);
		return ret;
	}

	mutex_init(&hotplug_tuners_ins.alu_hotplug_mutex);

	/* INITIALIZE PCPU VARS */
	for_each_possible_cpu(cpu) {
		struct hotplug_cpuinfo *pcpu_info = &per_cpu(od_hotplug_cpuinfo, cpu);

		pcpu_info->up_freq = hotplug_freq[cpu][UP_INDEX];
		pcpu_info->down_freq = hotplug_freq[cpu][DOWN_INDEX];
		pcpu_info->up_load = hotplug_load[cpu][UP_INDEX];
		pcpu_info->down_load = hotplug_load[cpu][DOWN_INDEX];
		pcpu_info->up_rq = hotplug_rq[cpu][UP_INDEX];
		pcpu_info->down_rq = hotplug_rq[cpu][DOWN_INDEX];
		pcpu_info->up_rate = hotplug_rate[cpu][UP_INDEX];
		pcpu_info->down_rate = hotplug_rate[cpu][DOWN_INDEX];
		pcpu_info->big_cpu = (bool)hotplug_cputype[cpu];
                pcpu_info->can_take_down = hotplug_initstate[cpu];
                pcpu_info->can_bring_up = !hotplug_initstate[cpu];
	}

#ifdef CONFIG_THERMAL_NOTIFICATION
	thermal_notif.notifier_call = thermal_notifier_callback;
#endif

	if (hotplug_tuners_ins.hotplug_enable > 0) {
		hotplug_start();
	}

	return ret;
}

static void __exit alucard_hotplug_exit(void)
{
	if (hotplug_tuners_ins.hotplug_enable > 0) {
		hotplug_stop();
	}

	mutex_destroy(&hotplug_tuners_ins.alu_hotplug_mutex);

	sysfs_remove_group(kernel_kobj, &alucard_hotplug_attr_group);
}
MODULE_AUTHOR("Alucard_24@XDA+AndreiC");
MODULE_DESCRIPTION("'alucard_hotplug' - Modified alucard hotplug for processors with 8 cores");
MODULE_LICENSE("GPL");

late_initcall(alucard_hotplug_init);
