/*
 * linux/drivers/devfreq/governor_passive.c
 *
 * Copyright (C) 2015 Samsung Electronics
 * Author: Chanwoo Choi <cw00.choi@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/devfreq.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/devfreq.h>
#include "governor.h"

static int devfreq_passive_get_target_freq(struct devfreq *passive,
					unsigned long *freq)
{
	struct devfreq_passive_data *passive_data = passive->data;
	struct devfreq *parent_devfreq = passive_data->parent;
	unsigned long child_freq = ULONG_MAX;
	int i, count;

	/*
	 * Each devfreq has the OPP table. After deciding the new frequency
	 * from the governor of parent devfreq device, the passive governor
	 * need to get the index of new frequency on OPP table of parent
	 * device. And then the index is used for getting the suitable
	 * new frequency for passive devfreq device.
	 */

	if (!passive->profile || !passive->profile->freq_table
		|| passive->profile->max_state <= 0)
		return -EINVAL;

	/*
	 * When new frequency is lower than previous frequency of parent
	 * devfreq device, passive governor get the correct frequency from OPP
	 * list of parent device. Because in this case, *freq is temporary
	 * value which is decided by ondemand governor.
	 */
	if (parent_devfreq->previous_freq > *freq) {
		struct dev_pm_opp *opp;
		opp = devfreq_recommended_opp(parent_devfreq->dev.parent,
						freq, 0);
		if (IS_ERR_OR_NULL(opp))
			return PTR_ERR(opp);
	}

	/*
	 * Get the OPP table's index of decided freqeuncy by governor
	 * of parent device.
	 */
	for (i = 0; i < parent_devfreq->profile->max_state; i++)
		if (parent_devfreq->profile->freq_table[i] == *freq)
			break;

	if (i == parent_devfreq->profile->max_state)
		return -EINVAL;
	count = passive->profile->max_state;

	/* Get the suitable frequency by using index of parent device. */
	if (i < passive->profile->max_state)
		child_freq = passive->profile->freq_table[i];
	else
		child_freq = passive->profile->freq_table[count - 1];

	/* Return the suitable frequency for passive device. */
	*freq = child_freq;

	return 0;
}

static int devfreq_passive_event_handler(struct devfreq *devfreq,
				unsigned int event, void *data)
{
	return 0;
}

static struct devfreq_governor devfreq_passive = {
	.name = "passive",
	.type = DEVFREQ_GOV_PASSIVE,
	.get_target_freq = devfreq_passive_get_target_freq,
	.event_handler = devfreq_passive_event_handler,
};

static int __init devfreq_passive_init(void)
{
	return devfreq_add_governor(&devfreq_passive);
}
subsys_initcall(devfreq_passive_init);

static void __exit devfreq_passive_exit(void)
{
	int ret;

	ret = devfreq_remove_governor(&devfreq_passive);
	if (ret)
		pr_err("%s: failed remove governor %d\n", __func__, ret);

	return;
}
module_exit(devfreq_passive_exit);

MODULE_AUTHOR("Chanwoo Choi <cw00.choi@samsung.com>");
MODULE_DESCRIPTION("DEVFREQ Passive governor");
MODULE_LICENSE("GPL v2");
