#ifndef _CEC_DEVNODE_H
#define _CEC_DEVNODE_H

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

/*
 * Flag to mark the cec_devnode struct as registered. Drivers must not touch
 * this flag directly, it will be set and cleared by cec_devnode_register and
 * cec_devnode_unregister.
 */
#define CEC_FLAG_REGISTERED	0

/**
 * struct cec_devnode - cec device node
 * @parent:	parent device
 * @minor:	device node minor number
 * @flags:	flags, combination of the CEC_FLAG_* constants
 *
 * This structure represents a cec-related device node.
 *
 * The @parent is a physical device. It must be set by core or device drivers
 * before registering the node.
 */
struct cec_devnode {
	/* sysfs */
	struct device dev;		/* cec device */
	struct cdev cdev;		/* character device */
	struct device *parent;		/* device parent */

	/* device info */
	int minor;
	bool dead;			/* Set when this node is unregistered */
	struct mutex fhs_lock;
	struct list_head fhs;		/* cec_fh list */
};

struct cec_adapter;
struct cec_data;

struct cec_data {
	struct list_head list;
	struct cec_adapter *adap;
	struct cec_msg msg;
	struct cec_fh *fh;
	struct delayed_work work;
	struct completion c;
	bool blocking;
	bool completed;
};

struct cec_msg_entry {
	struct list_head	list;
	struct cec_msg		msg;
};

#define CEC_NUM_EVENTS		CEC_EVENT_LOST_MSGS

struct cec_fh {
	struct list_head	list;
	struct cec_adapter	*adap;
	bool			monitor;

	/* Events */
	wait_queue_head_t	wait;
	struct cec_event	events[CEC_NUM_EVENTS];
	struct mutex		lock;
	struct list_head	msgs; /* queued messages */
	unsigned int		queued_msgs;
};

struct cec_adap_ops {
	/* Low-level callbacks */
	int (*adap_enable)(struct cec_adapter *adap, bool enable);
	int (*adap_log_addr)(struct cec_adapter *adap, u8 logical_addr);
	int (*adap_transmit)(struct cec_adapter *adap, u32 timeout_ms, struct cec_msg *msg);

	/* High-level callbacks */
	int (*received)(struct cec_adapter *adap, struct cec_msg *msg);
	u8 (*source_cdc_hpd)(struct cec_adapter *adap, u8 cdc_hpd_state);
	u8 (*sink_cdc_hpd)(struct cec_adapter *adap, u8 cdc_hpd_state, u8 cdc_hpd_error);
	int (*sink_initiate_arc)(struct cec_adapter *adap);
	int (*sink_terminate_arc)(struct cec_adapter *adap);
	int (*source_arc_initiated)(struct cec_adapter *adap);
	int (*source_arc_terminated)(struct cec_adapter *adap);
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
	const char *name;
	struct cec_devnode devnode;
	struct mutex lock;
	struct rc_dev *rc;

	struct list_head transmit_queue;
	struct list_head wait_queue;
	struct cec_data *transmitting;

	struct task_struct *kthread_config;

	struct task_struct *kthread;
	wait_queue_head_t kthread_waitq;
	wait_queue_head_t waitq;

	/* Can be set by the main driver: */
	const struct cec_adap_ops *ops;
	void *priv;
	u32 capabilities;
	u8 available_log_addrs;
	u8 pwr_state;
	u16 phys_addr;
	u32 vendor_id;
	u8 cec_version;

	u8 ninputs;
	u16 connected_inputs;
	bool is_source;
	bool is_enabled;
	bool is_configuring;
	bool is_configured;
	u8 num_log_addrs;
	struct cec_fh *cec_owner;
	u8 prim_device[CEC_MAX_LOG_ADDRS];
	u8 log_addr_type[CEC_MAX_LOG_ADDRS];
	u8 log_addr[CEC_MAX_LOG_ADDRS];
	u8 all_device_types[CEC_MAX_LOG_ADDRS];
	u8 features[CEC_MAX_LOG_ADDRS][12];
	u16 phys_addrs[15];
	char osd_name[15];
	u8 passthrough;
	u32 sequence;

	char input_name[32];
	char input_phys[32];
	char input_drv[32];
};

#define to_cec_adapter(node) container_of(node, struct cec_adapter, devnode)

struct cec_adapter *cec_create_adapter(const struct cec_adap_ops *ops,
		       void *priv, const char *name, u32 caps,
		       u8 ninputs, struct module *owner, struct device *parent);
void cec_delete_adapter(struct cec_adapter *adap);
int cec_transmit_msg(struct cec_adapter *adap, struct cec_msg *msg,
		     bool block);
int cec_claim_log_addrs(struct cec_adapter *adap,
			struct cec_log_addrs *log_addrs, bool block);
int cec_enable(struct cec_adapter *adap, bool enable);
u8 cec_sink_cdc_hpd(struct cec_adapter *adap, u8 input_port, u8 cdc_hpd_state);
void cec_log_status(struct cec_adapter *adap);

/* Called by the adapter */
void cec_transmit_done(struct cec_adapter *adap, u32 status);
void cec_received_msg(struct cec_adapter *adap, struct cec_msg *msg);
void cec_connected_inputs(struct cec_adapter *adap, u16 connected_inputs);

#endif /* _CEC_DEVNODE_H */
