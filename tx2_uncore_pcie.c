// SPDX-License-Identifier: GPL-2.0
/*
 * Marvell THUNDERX2 SoC PCIE PMU UNCORE
 * Copyright (C) 2018 marvell Inc.
 * Author: Ganapatrao Kulkarni <gkulkarni@marvell.com>
 */

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/cpuhotplug.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>

#define TX2_PMU_HRTIMER_INTERVAL	(1 * NSEC_PER_SEC)
#define GET_EVENTID(ev)			((ev->hw.config) & 0xf)
#define GET_COUNTERID(ev)		((ev->hw.idx) & 0xf)

#define TX2_PCIE_MAX_COUNTERS		2
#define PCIE_STATIS_CTRL		0x1940
#define PCIE_TXTLP_OFFSET		0x1944
#define PCIE_RXTLP_OFFSET		0x195C
#define TX2_PCI_BAR_BASE		0x402800000ULL
#define TX2_PCI_BAR_BASE_NODE(n)	(TX2_PCI_BAR_BASE | (n << 30))

static const unsigned long pcie_event_hw_offset[] = {
	PCIE_TXTLP_OFFSET,
	PCIE_RXTLP_OFFSET
};

static unsigned long pcie_rc_base[2];
static LIST_HEAD(tx2_pmus);

struct tx2_uncore_pmu {
	struct hlist_node hpnode;
	struct list_head  entry;
	struct pmu pmu;
	char *name;
	int node;
	int cpu;
	u32 max_counters;
	u32 max_events;
	u64 hrtimer_interval;
	void __iomem *base;
	DECLARE_BITMAP(active_counters, TX2_PCIE_MAX_COUNTERS);
	struct perf_event *events[TX2_PCIE_MAX_COUNTERS];
	struct hrtimer hrtimer;
	const struct attribute_group **attr_groups;
};

static inline struct tx2_uncore_pmu *pmu_to_tx2_pmu(struct pmu *pmu)
{
	return container_of(pmu, struct tx2_uncore_pmu, pmu);
}

PMU_FORMAT_ATTR(event,	"config:0-1");

static struct attribute *pcie_pmu_format_attrs[] = {
	&format_attr_event.attr,
	NULL,
};

static const struct attribute_group pcie_pmu_format_attr_group = {
	.name = "format",
	.attrs = pcie_pmu_format_attrs,
};

/*
 * sysfs event attributes
 */
static ssize_t tx2_pmu_event_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct dev_ext_attribute *eattr;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	return sprintf(buf, "event=0x%lx\n", (unsigned long) eattr->var);
}

#define TX2_EVENT_ATTR(name, config) \
	PMU_EVENT_ATTR(name, tx2_pmu_event_attr_##name, \
			config, tx2_pmu_event_show)

enum PCIE_PERF_EVENTS {
	PCIE_PERF_TLP_TX,
	PCIE_PERF_TLP_RX,
	PCIE_PERF_EVENT_MAX
};

TX2_EVENT_ATTR(tlp_tx, PCIE_PERF_TLP_TX);
TX2_EVENT_ATTR(tlp_rx, PCIE_PERF_TLP_RX);

static struct attribute *pcie_pmu_events_attrs[] = {
	&tx2_pmu_event_attr_tlp_tx.attr.attr,
	&tx2_pmu_event_attr_tlp_rx.attr.attr,
	NULL
};

static const struct attribute_group pcie_pmu_events_attr_group = {
	.name = "events",
	.attrs = pcie_pmu_events_attrs,
};

/*
 * sysfs cpumask attributes
 */
static ssize_t cpumask_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	struct tx2_uncore_pmu *tx2_pmu;

	tx2_pmu = pmu_to_tx2_pmu(dev_get_drvdata(dev));
	return cpumap_print_to_pagebuf(true, buf, cpumask_of(tx2_pmu->cpu));
}
static DEVICE_ATTR_RO(cpumask);

static struct attribute *tx2_pmu_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static const struct attribute_group pmu_cpumask_attr_group = {
	.attrs = tx2_pmu_cpumask_attrs,
};

/*
 * Per PMU device attribute groups
 */
static const struct attribute_group *pcie_pmu_attr_groups[] = {
	&pcie_pmu_format_attr_group,
	&pmu_cpumask_attr_group,
	&pcie_pmu_events_attr_group,
	NULL
};

static inline u32 reg_readl(unsigned long addr)
{
	return readl((void __iomem *)addr);
}

static inline void reg_writel(u32 val, unsigned long addr)
{
	writel(val, (void __iomem *)addr);
}

static int alloc_counter(struct tx2_uncore_pmu *tx2_pmu)
{
	int counter;

	counter = find_first_zero_bit(tx2_pmu->active_counters,
				tx2_pmu->max_counters);
	if (counter == tx2_pmu->max_counters)
		return -ENOSPC;

	set_bit(counter, tx2_pmu->active_counters);
	return counter;
}

static inline void free_counter(struct tx2_uncore_pmu *tx2_pmu, int counter)
{
	clear_bit(counter, tx2_pmu->active_counters);
}

static void tx2_uncore_event_update(struct perf_event *event)
{
	s64 prev, delta, new = 0;
	struct hw_perf_event *hwc = &event->hw;
	struct tx2_uncore_pmu *tx2_pmu;

	tx2_pmu = pmu_to_tx2_pmu(event->pmu);

	new = reg_readl(hwc->event_base);
	new |= (u64)reg_readl(hwc->event_base + 4) << 32;
	prev = local64_xchg(&hwc->prev_count, new);
	delta = new - prev;
	local64_add(delta , &event->count);
}

static bool tx2_uncore_validate_event(struct pmu *pmu,
				  struct perf_event *event, int *counters)
{
	if (is_software_event(event))
		return true;
	/* Reject groups spanning multiple HW PMUs. */
	if (event->pmu != pmu)
		return false;

	*counters = *counters + 1;
	return true;
}

/*
 * Make sure the group of events can be scheduled at once
 * on the PMU.
 */
static bool tx2_uncore_validate_event_group(struct perf_event *event)
{
	struct perf_event *sibling, *leader = event->group_leader;
	int counters = 0;
	struct tx2_uncore_pmu *tx2_pmu;

	tx2_pmu = pmu_to_tx2_pmu(event->pmu);

	if (event->group_leader == event)
		return true;

	if (!tx2_uncore_validate_event(event->pmu, leader, &counters))
		return false;

	for_each_sibling_event(sibling, leader) {
		if (!tx2_uncore_validate_event(event->pmu, sibling, &counters))
			return false;
	}

	if (!tx2_uncore_validate_event(event->pmu, event, &counters))
		return false;

	/*
	 * If the group requires more counters than the HW has,
	 * it cannot ever be scheduled.
	 */
	return counters < tx2_pmu->max_counters;
}

static int tx2_uncore_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct tx2_uncore_pmu *tx2_pmu;

	/*
	 * SOC PMU counters are shared across all cores.
	 * Therefore, it does not support per-process mode.
	 * Also, it does not support event sampling mode.
	 */
	if (is_sampling_event(event) || event->attach_state & PERF_ATTACH_TASK)
		return -EINVAL;

	/* We have no filtering of any kind */
	if (event->attr.exclude_user	||
	    event->attr.exclude_kernel	||
	    event->attr.exclude_hv	||
	    event->attr.exclude_idle	||
	    event->attr.exclude_host	||
	    event->attr.exclude_guest)
		return -EINVAL;

	if (event->cpu < 0)
		return -EINVAL;

	tx2_pmu = pmu_to_tx2_pmu(event->pmu);
	if (tx2_pmu->cpu >= nr_cpu_ids)
		return -EINVAL;
	event->cpu = tx2_pmu->cpu;

	if (event->attr.config >= tx2_pmu->max_events)
		return -EINVAL;

	/* store event id */
	hwc->config = event->attr.config;

	/* Validate the group */
	if (!tx2_uncore_validate_event_group(event))
		return -EINVAL;

	return 0;
}

static void tx2_uncore_event_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct tx2_uncore_pmu *tx2_pmu;

	hwc->state = 0;
	tx2_pmu = pmu_to_tx2_pmu(event->pmu);

	reg_writel(1, hwc->config_base);
	perf_event_update_userpage(event);

	/* Start timer for first event */
	if (bitmap_weight(tx2_pmu->active_counters,
				tx2_pmu->max_counters) == 1) {
		hrtimer_start(&tx2_pmu->hrtimer,
			ns_to_ktime(tx2_pmu->hrtimer_interval),
			HRTIMER_MODE_REL_PINNED);
	}
}

static void tx2_uncore_event_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct tx2_uncore_pmu *tx2_pmu;

	if (hwc->state & PERF_HES_UPTODATE)
		return;

	tx2_pmu = pmu_to_tx2_pmu(event->pmu);
	reg_writel(0, hwc->config_base);
	WARN_ON_ONCE(hwc->state & PERF_HES_STOPPED);
	hwc->state |= PERF_HES_STOPPED;
	if (flags & PERF_EF_UPDATE) {
		tx2_uncore_event_update(event);
		hwc->state |= PERF_HES_UPTODATE;
	}
}

static int tx2_uncore_event_add(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct tx2_uncore_pmu *tx2_pmu;

	tx2_pmu = pmu_to_tx2_pmu(event->pmu);

	/* Allocate a free counter */
	hwc->idx  = alloc_counter(tx2_pmu);
	if (hwc->idx < 0)
		return -EAGAIN;

	tx2_pmu->events[hwc->idx] = event;

	/* set counter control and data registers base address */
	hwc->config_base = (unsigned long)tx2_pmu->base + PCIE_STATIS_CTRL;
	hwc->event_base =  (unsigned long)tx2_pmu->base +
		pcie_event_hw_offset[GET_EVENTID(event)];

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (flags & PERF_EF_START)
		tx2_uncore_event_start(event, flags);

	return 0;
}

static void tx2_uncore_event_del(struct perf_event *event, int flags)
{
	struct tx2_uncore_pmu *tx2_pmu = pmu_to_tx2_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	tx2_uncore_event_stop(event, PERF_EF_UPDATE);

	/* clear the assigned counter */
	free_counter(tx2_pmu, GET_COUNTERID(event));

	perf_event_update_userpage(event);
	tx2_pmu->events[hwc->idx] = NULL;
	hwc->idx = -1;
}

static void tx2_uncore_event_read(struct perf_event *event)
{
	tx2_uncore_event_update(event);
}

static enum hrtimer_restart tx2_hrtimer_callback(struct hrtimer *timer)
{
	struct tx2_uncore_pmu *tx2_pmu;
	int max_counters, idx;
	struct perf_event *event = NULL;

	tx2_pmu = container_of(timer, struct tx2_uncore_pmu, hrtimer);
	max_counters = tx2_pmu->max_counters;

	if (bitmap_empty(tx2_pmu->active_counters, max_counters))
		return HRTIMER_NORESTART;

	for_each_set_bit(idx, tx2_pmu->active_counters, max_counters) {
		event = tx2_pmu->events[idx];
		tx2_uncore_event_update(event);
	}

	hrtimer_forward_now(timer, ns_to_ktime(tx2_pmu->hrtimer_interval));
	return HRTIMER_RESTART;
}

static int tx2_uncore_pmu_register(
		struct tx2_uncore_pmu *tx2_pmu)
{
	char *name = tx2_pmu->name;

	/* Perf event registration */
	tx2_pmu->pmu = (struct pmu) {
		.module         = THIS_MODULE,
		.attr_groups	= tx2_pmu->attr_groups,
		.task_ctx_nr	= perf_invalid_context,
		.event_init	= tx2_uncore_event_init,
		.add		= tx2_uncore_event_add,
		.del		= tx2_uncore_event_del,
		.start		= tx2_uncore_event_start,
		.stop		= tx2_uncore_event_stop,
		.read		= tx2_uncore_event_read,
	};

	tx2_pmu->pmu.name = kasprintf(GFP_KERNEL, "%s", name);

	return perf_pmu_register(&tx2_pmu->pmu, tx2_pmu->pmu.name, -1);
}

static int tx2_uncore_pmu_add_dev(struct tx2_uncore_pmu *tx2_pmu)
{
	int ret, cpu;

	cpu = cpumask_any_and(cpumask_of_node(tx2_pmu->node),
			cpu_online_mask);

	tx2_pmu->cpu = cpu;
	hrtimer_init(&tx2_pmu->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	tx2_pmu->hrtimer.function = tx2_hrtimer_callback;

	ret = tx2_uncore_pmu_register(tx2_pmu);
	if (ret) {
		pr_err("%s PMU: Failed to init driver\n", tx2_pmu->name);
		return -ENODEV;
	}

	if (ret) {
		pr_err("Error %d registering hotplug", ret);
		return ret;
	}

	/* Add to list */
	list_add(&tx2_pmu->entry, &tx2_pmus);

	pr_debug("%s pcie PMU registered\n", tx2_pmu->pmu.name);
	return ret;
}

static struct tx2_uncore_pmu *tx2_uncore_pmu_init_dev(struct pci_dev *pdev)
{
	struct tx2_uncore_pmu *tx2_pmu;
	void __iomem *base;
	int node = pcibus_to_node(pdev->bus), rc;

	tx2_pmu = kzalloc(sizeof(*tx2_pmu), GFP_KERNEL);
	if (!tx2_pmu)
		return NULL;

	rc = PCI_SLOT(pdev->devfn);
	base = (void __iomem *) (pcie_rc_base[node] + (rc - 1) * SZ_128K);

	tx2_pmu->base = base;
	tx2_pmu->node = node;
	INIT_LIST_HEAD(&tx2_pmu->entry);

	tx2_pmu->max_counters = TX2_PCIE_MAX_COUNTERS;
	tx2_pmu->max_events = PCIE_PERF_EVENT_MAX;
	tx2_pmu->hrtimer_interval = TX2_PMU_HRTIMER_INTERVAL;
	tx2_pmu->attr_groups = pcie_pmu_attr_groups;
	tx2_pmu->name = kasprintf( GFP_KERNEL, "uncore_pcie_%d", (node * 14) + rc);

	return tx2_pmu;
}

static int tx2_uncore_pmu_add(struct pci_dev *pdev)
{
	struct tx2_uncore_pmu *tx2_pmu;

	tx2_pmu = tx2_uncore_pmu_init_dev(pdev);

	if (!tx2_pmu)
		return -1;

	if (tx2_uncore_pmu_add_dev(tx2_pmu)) {
		return -1;
	}
	return 0;
}

static int __init pcie_perf_init(void)
{
	int node;
	struct pci_dev *pdev = NULL;

	for_each_online_node(node) {
		pcie_rc_base[node] = (u64)ioremap(TX2_PCI_BAR_BASE_NODE(node), 14 * SZ_128K );
		if (!pcie_rc_base[node]) {
			pr_info("Couldn't ioremap for node %d", node);
			return -ENOMEM;
		}
	}

	for_each_pci_dev(pdev) {
		if (pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT)
			tx2_uncore_pmu_add(pdev);
	}

	pr_info("pcie perf module loaded\n");
	return 0;
}

void pcie_perf_exit(void)
{
	struct tx2_uncore_pmu *tx2_pmu, *temp;
	int node;

	if (!list_empty(&tx2_pmus)) {
		list_for_each_entry_safe(tx2_pmu, temp, &tx2_pmus, entry) {
			perf_pmu_unregister(&tx2_pmu->pmu);
			list_del(&tx2_pmu->entry);
			kfree(tx2_pmu);
		}
	}

	for_each_online_node(node)
		iounmap((void*)pcie_rc_base[node]);

	pr_info("pcie perf module unloaded\n");
}

module_init(pcie_perf_init);
module_exit(pcie_perf_exit);


MODULE_DESCRIPTION("ThunderX2 pcie UNCORE PMU driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ganapatrao Kulkarni <gkulkarni@marvell.com>");
