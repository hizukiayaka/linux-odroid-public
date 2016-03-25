#ifndef _CEC_MEDIA_H
#define _CEC_MEDIA_H

#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/cec-funcs.h>
#include <media/rc-core.h>

#define cec_phys_addr_exp(pa) \
	((pa) >> 12), ((pa) >> 8) & 0xf, ((pa) >> 4) & 0xf, (pa) & 0xf

/**
 * struct cec_devnode - cec device node
 * @dev:	cec device
 * @cdev:	cec character device
 * @parent:	parent device
 * @minor:	device node minor number
 * @registered:	the device was correctly registered
 * @unregistered: the device was unregistered
 * @fhs_lock:	lock to control access to the filehandle list
 * @fhs:	the list of open filehandles (cec_fh)
 *
 * This structure represents a cec-related device node.
 *
 * The @parent is a physical device. It must be set by core or device drivers
 * before registering the node.
 */
struct cec_devnode {
	/* sysfs */
	struct device dev;
	struct cdev cdev;
	struct device *parent;

	/* device info */
	int minor;
	bool registered;
	bool unregistered;
	struct mutex fhs_lock;
	struct list_head fhs;
};

struct cec_adapter;
struct cec_data;

struct cec_data {
	struct list_head list;
	struct list_head xfer_list;
	struct cec_adapter *adap;
	struct cec_msg msg;
	struct cec_fh *fh;
	struct delayed_work work;
	struct completion c;
	u8 attempts;
	bool new_initiator;
	bool blocking;
	bool completed;
};

struct cec_msg_entry {
	struct list_head	list;
	struct cec_msg		msg;
};

#define CEC_NUM_EVENTS		CEC_EVENT_LOST_MSGS

struct cec_event_queue {
	unsigned		elems;
	unsigned		num_events;
	struct cec_event	*events;
};

struct cec_fh {
	struct list_head	list;
	struct list_head	xfer_list;
	struct cec_adapter	*adap;
	u8			mode_initiator;
	u8			mode_follower;

	/* Events */
	wait_queue_head_t	wait;
	unsigned		events;
	struct cec_event_queue	evqueue[CEC_NUM_EVENTS];
	struct mutex		lock;
	struct list_head	msgs; /* queued messages */
	unsigned		queued_msgs;
	unsigned		lost_msgs;
};

#define CEC_SIGNAL_FREE_TIME_RETRY		3
#define CEC_SIGNAL_FREE_TIME_NEW_INITIATOR	5
#define CEC_SIGNAL_FREE_TIME_NEXT_XFER		7

/* The nominal data bit period is 2.4 ms */
#define CEC_FREE_TIME_TO_USEC(ft)		((ft) * 2400)

struct cec_adap_ops {
	/* Low-level callbacks */
	int (*adap_enable)(struct cec_adapter *adap, bool enable);
	int (*adap_monitor_all_enable)(struct cec_adapter *adap, bool enable);
	int (*adap_log_addr)(struct cec_adapter *adap, u8 logical_addr);
	int (*adap_transmit)(struct cec_adapter *adap, u8 attempts,
			     u32 signal_free_time, struct cec_msg *msg);
	void (*adap_log_status)(struct cec_adapter *adap);

	/* High-level CEC message callback */
	int (*received)(struct cec_adapter *adap, struct cec_msg *msg);
};

/*
 * The minimum message length you can receive (excepting poll messages) is 2.
 * With a transfer rate of at most 36 bytes per second this makes 18 messages
 * per second worst case.
 *
 * We queue at most 10 seconds worth of messages.
 */
#define CEC_MAX_MSG_QUEUE_SZ		(18 * 10)

struct cec_adapter {
	struct module *owner;
	char name[32];
	struct cec_devnode devnode;
	struct mutex lock;
	struct rc_dev *rc;

	struct list_head transmit_queue;
	struct list_head wait_queue;
	struct cec_data *transmitting;

	struct task_struct *kthread_config;
	struct completion config_completion;

	struct task_struct *kthread;
	wait_queue_head_t kthread_waitq;
	wait_queue_head_t waitq;

	/* Can be set by the main driver: */
	const struct cec_adap_ops *ops;
	void *priv;
	u32 capabilities;
	u8 available_log_addrs;

	u16 phys_addr; /* call cec_s_phys_addr() to change this */
	bool is_source;
	bool is_configuring;
	bool is_configured;
	u32 monitor_all_cnt;
	u32 follower_cnt;
	struct cec_fh *cec_follower;
	struct cec_fh *cec_initiator;
	bool passthrough;
	struct cec_log_addrs log_addrs;

	u16 phys_addrs[15];
	u32 sequence;

	char input_name[32];
	char input_phys[32];
	char input_drv[32];
};

static inline bool cec_has_log_addr(const struct cec_adapter *adap, u8 log_addr)
{
	return adap->log_addrs.log_addr_mask & (1 << log_addr);
}

/* Two helper functions to get/set the physical address in the EDID */
u16 cec_get_edid_phys_addr(const u8 *edid, unsigned size, unsigned *offset);
void cec_set_edid_phys_addr(u8 *edid, unsigned size, u16 phys_addr);
/*
 * Calculate the physical address for an input based on the parent's
 * physical address
 */
u16 cec_phys_addr_for_input(u16 phys_addr, u8 input);
u16 cec_phys_addr_parent(u16 phys_addr);

#define to_cec_adapter(node) container_of(node, struct cec_adapter, devnode)

struct cec_adapter *cec_create_adapter(const struct cec_adap_ops *ops,
		void *priv, const char *name, u32 caps, u8 available_las,
		struct device *parent);
int cec_register_adapter(struct cec_adapter *adap);
void cec_unregister_adapter(struct cec_adapter *adap);
void cec_delete_adapter(struct cec_adapter *adap);

int cec_s_log_addrs(struct cec_adapter *adap, struct cec_log_addrs *log_addrs,
		    bool block);
void cec_s_phys_addr(struct cec_adapter *adap, u16 phys_addr,
		     bool block);
void cec_s_available_log_addrs(struct cec_adapter *adap, u8 available_las);
int cec_transmit_msg(struct cec_adapter *adap, struct cec_msg *msg,
		     bool block);

void cec_log_status(struct cec_adapter *adap, struct cec_fh *fh);

/* Called by the adapter */
void cec_transmit_done(struct cec_adapter *adap, u8 status, u8 arb_lost_cnt,
		       u8 nack_cnt, u8 low_drive_cnt, u8 error_cnt);
void cec_received_msg(struct cec_adapter *adap, struct cec_msg *msg);

#endif /* _CEC_MEDIA_H */
