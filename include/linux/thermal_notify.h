#ifndef __LINUX_THERMAL_NOTIFY_H
#define __LINUX_THERMAL_NOTIFY_H

#include <linux/notifier.h>

typedef enum {
	/* the cpus have hit the thermal limit */
	THERMAL_EVENT_CPUS_LIMIT_HIT = 0,
	/* the cpus are at the hottest level */
	THERMAL_EVENT_CPUS_HOTTEST,
	/* the cpus are becoming hotter */
	THERMAL_EVENT_CPUS_HOTTER,
	/* the cpus are becoming hot */
	THERMAL_EVENT_CPUS_HOT,
	/* the cpus are becoming warming */
	THERMAL_EVENT_CPUS_WARMING,
	/* the cpus are in the temperature limit */
	THERMAL_EVENT_CPUS_COLD
} thermal_cpu_limits;

#define NR_CLUSTERS 2
#define LITTLE_CLUSTER 1
#define BIG_CLUSTER 0

struct thermal_event {
	void *data;
};

#ifdef CONFIG_THERMAL_NOTIFICATION
int thermal_register_client(struct notifier_block *nb);
int thermal_unregister_client(struct notifier_block *nb);
int thermal_notifier_call_chain(unsigned long val, void *v);
void init_max_cluster_freq(void);
void set_cluster_max_freq(unsigned int cluster_nr, unsigned int freq);
unsigned int get_cluster_max_freq(unsigned int cluster_nr);
#else
static int inline thermal_register_client(struct notifier_block *nb)
{
	return -ENOENT;
}
static int inline thermal_unregister_client(struct notifier_block *nb)
{
	return -ENOENT;
}
static int inline thermal_notifier_call_chain(unsigned long val, void *v)
{
	return -ENOENT;
}
static void init_max_cluster_freq(void)
{
}
static void set_cluster_max_freq(unsigned int cluster_nr, unsigned int freq)
{
}
static unsigned int get_cluster_max_freq(unsigned int cluster_nr)
{
	return UINT_MAX;
}
#endif
#endif /* _LINUX_THERMAL_NOTIFY_H */

