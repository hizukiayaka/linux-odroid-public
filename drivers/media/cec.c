#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <media/cec.h>

#define CEC_NUM_DEVICES	256
#define CEC_NAME	"cec"

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "debug level (0-2)");

#define dprintk(lvl, fmt, arg...)					\
	do {								\
		if (lvl <= debug)					\
			pr_info("cec-%s: " fmt, adap->name, ## arg);	\
	} while (0)

static dev_t cec_dev_t;

/* Active devices */
static DEFINE_MUTEX(cec_devnode_lock);
static DECLARE_BITMAP(cec_devnode_nums, CEC_NUM_DEVICES);

/* dev to cec_devnode */
#define to_cec_devnode(cd) container_of(cd, struct cec_devnode, dev)

static inline struct cec_devnode *cec_devnode_data(struct file *filp)
{
	struct cec_fh *fh = filp->private_data;

	return &fh->adap->devnode;
}

static bool cec_pa_are_adjacent(const struct cec_adapter *adap, u16 pa1, u16 pa2)
{
	u16 mask = 0xf000;
	int i;

	if (pa1 == CEC_PHYS_ADDR_INVALID || pa2 == CEC_PHYS_ADDR_INVALID)
		return false;
	for (i = 0; i < 3; i++) {
		if ((pa1 & mask) != (pa2 & mask))
			break;
		mask = (mask >> 4) | 0xf000;
	}
	if ((pa1 & ~mask) || (pa2 & ~mask))
		return false;
	if (!(pa1 & mask) ^ !(pa2 & mask))
		return true;
	return false;
}

static bool cec_la_are_adjacent(const struct cec_adapter *adap, u8 la1, u8 la2)
{
	u16 pa1 = adap->phys_addrs[la1];
	u16 pa2 = adap->phys_addrs[la2];

	return cec_pa_are_adjacent(adap, pa1, pa2);
}

static int cec_log_addr2idx(const struct cec_adapter *adap, u8 log_addr)
{
	int i;

	for (i = 0; i < adap->num_log_addrs; i++)
		if (adap->log_addr[i] == log_addr)
			return i;
	return -1;
}

static unsigned cec_log_addr2dev(const struct cec_adapter *adap, u8 log_addr)
{
	int i = cec_log_addr2idx(adap, log_addr);

	return adap->prim_device[i < 0 ? 0 : i];
}

static void cec_queue_msg_fh(struct cec_fh *fh, const struct cec_msg *msg)
{
	struct cec_msg_entry *entry;
	struct cec_event *ev = &fh->events[CEC_EVENT_LOST_MSGS - 1];

	mutex_lock(&fh->lock);
	if (fh->queued_msgs == CEC_MAX_MSG_QUEUE_SZ)
		goto lost_msgs;
	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		goto lost_msgs;

	entry->msg = *msg;
	list_add(&entry->list, &fh->msgs);
	fh->queued_msgs++;
	mutex_unlock(&fh->lock);
	wake_up_interruptible(&fh->wait);
	return;

lost_msgs:
	if (ev->event == 0) {
		ev->ts = ktime_get_ns();
		ev->event = CEC_EVENT_LOST_MSGS;
	}
	mutex_unlock(&fh->lock);
	wake_up_interruptible(&fh->wait);
}

static void cec_queue_msg_monitor(struct cec_adapter *adap,
				  const struct cec_msg *msg)
{
	struct cec_fh *fh;

	mutex_lock(&adap->devnode.fhs_lock);
	list_for_each_entry(fh, &adap->devnode.fhs, list) {
		if (fh->monitor)
			cec_queue_msg_fh(fh, msg);
	}
	mutex_unlock(&adap->devnode.fhs_lock);
}

static void cec_post_state_event_fh(struct cec_adapter *adap,
				    struct cec_fh *fh, u64 ts)
{
	struct cec_event *ev = &fh->events[CEC_EVENT_STATE_CHANGE - 1];
	struct cec_event_state_change *ch = &ev->state_change;

	mutex_lock(&fh->lock);
	ev->ts = ts;
	ev->event = CEC_EVENT_STATE_CHANGE;
	if (!adap->is_enabled)
		ch->state = CEC_EVENT_STATE_DISABLED;
	else if (adap->is_configuring)
		ch->state = CEC_EVENT_STATE_CONFIGURING;
	else if (adap->is_configured)
		ch->state = CEC_EVENT_STATE_CONFIGURED;
	else
		ch->state = CEC_EVENT_STATE_UNCONFIGURED;
	mutex_unlock(&fh->lock);
	wake_up_interruptible(&fh->wait);
}

static void cec_post_state_event(struct cec_adapter *adap)
{
	u64 ts = ktime_get_ns();
	struct cec_fh *fh;

	mutex_lock(&adap->devnode.fhs_lock);
	list_for_each_entry(fh, &adap->devnode.fhs, list)
		cec_post_state_event_fh(adap, fh, ts);
	mutex_unlock(&adap->devnode.fhs_lock);
}

static void cec_data_completed(struct cec_data *data)
{
	if (data->blocking) {
		/*
		 * Someone is blocking so mark the message as completed
		 * and call complete.
		 */
		data->completed = true;
		complete(&data->c);
	} else {
		/*
		 * No blocking, so just queue the message if needed and
		 * free the memory.
		 */
		if (data->fh)
			cec_queue_msg_fh(data->fh, &data->msg);
		kfree(data);
	}
}

/*
 * Main CEC state machine
 *
 * Wait until the thread should be stopped, or we're not transmitting and
 * a new transmit message is queued up, in which case we start transmitting
 * that message. When the adapter finished transmitting the message it will
 * call cec_transmit_done().
 *
 * If the adapter is disabled, then remove all queued messages instead.
 */
static int cec_thread_func(void *_adap)
{
	struct cec_adapter *adap = _adap;

	for (;;) {
		struct cec_data *data;
		u32 timeout;

		wait_event_interruptible(adap->kthread_waitq,
			kthread_should_stop() ||
			(!adap->transmitting &&
			 !list_empty(&adap->transmit_queue)));

		if (kthread_should_stop())
			break;
		mutex_lock(&adap->lock);

		if (!adap->is_enabled) {
			while (!list_empty(&adap->transmit_queue)) {
				data = list_first_entry(&adap->transmit_queue,
							struct cec_data, list);
				list_del(&data->list);
				data->msg.ts = ktime_get_ns();
				data->msg.status = CEC_TX_STATUS_RETRY_TIMEOUT;
				data->msg.reply = 0;
				cec_data_completed(data);
			}
			goto unlock;
		}

		if (list_empty(&adap->transmit_queue))
			goto unlock;

		data = list_first_entry(&adap->transmit_queue,
					struct cec_data, list);
		list_del(&data->list);
		adap->transmitting = data;
		timeout = data->msg.len == 1 ? 200 : 1000;
		adap->ops->adap_transmit(adap, timeout, &data->msg);
unlock:
		mutex_unlock(&adap->lock);
	}
	return 0;
}

void cec_transmit_done(struct cec_adapter *adap, u32 status)
{
	dprintk(2, "cec_transmit_done\n");
	mutex_lock(&adap->lock);
	if (WARN_ON(adap->transmitting == NULL)) {
		dprintk(0, "cec_transmit_done without an ongoing transmit!\n");
	} else {
		struct cec_data *data = adap->transmitting;
		struct cec_msg *msg = &data->msg;

		msg->ts = ktime_get_ns();
		msg->status = status;
		if (status || !adap->is_configured)
			msg->reply = 0;
		/* Queue transmitted message for monitoring purposes */
		cec_queue_msg_monitor(adap, msg);
		adap->transmitting = NULL;
		if (msg->reply) {
			/*
			 * We want to wait for a reply, so queue the message to
			 * the wait_queue and schedule a timeout task.
			 */
			if (msg->timeout == 0)
				msg->timeout = 1000;
			list_add_tail(&data->list, &adap->wait_queue);
			schedule_delayed_work(&data->work,
					      msecs_to_jiffies(msg->timeout));
		} else {
			cec_data_completed(data);
		}
		/*
		 * Wake up the main thread to see if another message is ready
		 * for transmitting.
		 */
		wake_up_interruptible(&adap->kthread_waitq);
	}
	mutex_unlock(&adap->lock);
}
EXPORT_SYMBOL_GPL(cec_transmit_done);

/*
 * Called when waiting for a reply times out.
 */
static void cec_wait_timeout(struct work_struct *work)
{
	struct cec_data *data = container_of(work, struct cec_data, work.work);
	struct cec_adapter *adap = data->adap;

	mutex_lock(&adap->lock);
	if (list_empty(&data->list))
		goto unlock;

	list_del_init(&data->list);
	data->msg.ts = ktime_get_ns();
	data->msg.status = CEC_TX_STATUS_REPLY_TIMEOUT;
	cec_data_completed(data);
unlock:
	mutex_unlock(&adap->lock);
}

static int cec_transmit_msg_fh(struct cec_adapter *adap, struct cec_msg *msg,
			       struct cec_fh *fh, bool block)
{
	struct cec_data *data;
	int res = 0;

	if (msg->len == 0 || msg->len > 16) {
		dprintk(1, "cec_transmit_msg: invalid length %d\n", msg->len);
		return -EINVAL;
	}
	if (msg->reply && (msg->len == 1 || (cec_msg_is_broadcast(msg)))) {
		dprintk(1, "cec_transmit_msg: can't reply for poll or broadcast msg\n");
		return -EINVAL;
	}
	if (msg->len > 1 && !cec_msg_is_broadcast(msg) &&
	    cec_msg_initiator(msg) == cec_msg_destination(msg)) {
		dprintk(1, "cec_transmit_msg: initiator == destination\n");
		return -EINVAL;
	}
	if (cec_msg_initiator(msg) != 0xf &&
	    cec_log_addr2idx(adap, cec_msg_initiator(msg)) < 0) {
		dprintk(1, "cec_transmit_msg: initiator has unknown logical address\n");
		return -EINVAL;
	}
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	if (msg->len == 1)
		dprintk(2, "cec_transmit_msg: 0x%02x%s\n",
				msg->msg[0], !block ? " nb" : "");
	else if (msg->reply)
		dprintk(2, "cec_transmit_msg: 0x%02x 0x%02x (wait for 0x%02x)%s\n",
				msg->msg[0], msg->msg[1],
				msg->reply, !block ? " nb" : "");
	else
		dprintk(2, "cec_transmit_msg: 0x%02x 0x%02x%s\n",
				msg->msg[0], msg->msg[1],
				!block ? " nb" : "");

	if (msg->len > 1 && msg->msg[1] == CEC_MSG_CDC_MESSAGE) {
		msg->msg[2] = adap->phys_addr >> 8;
		msg->msg[3] = adap->phys_addr & 0xff;
	}
	data->msg = *msg;
	data->fh = fh;
	data->adap = adap;
	data->blocking = block;
	init_completion(&data->c);
	INIT_DELAYED_WORK(&data->work, cec_wait_timeout);

	mutex_lock(&adap->lock);
	if (adap->is_configured || adap->is_configuring) {
		data->msg.sequence = adap->sequence++;
		list_add_tail(&data->list, &adap->transmit_queue);
		if (adap->transmitting == NULL)
			wake_up_interruptible(&adap->kthread_waitq);
	} else {
		res = -ENONET;
		kfree(data);
	}
	mutex_unlock(&adap->lock);
	if (res || !block)
		return res;
	res = wait_for_completion_interruptible(&data->c);
	mutex_lock(&adap->lock);
	if (data->completed) {
		*msg = data->msg;
		kfree(data);
		res = 0;
	} else {
		data->blocking = false;
		data->fh = NULL;
	}
	mutex_unlock(&adap->lock);
	return res;
}

int cec_transmit_msg(struct cec_adapter *adap, struct cec_msg *msg,
		     bool block)
{
	return cec_transmit_msg_fh(adap, msg, NULL, block);
}
EXPORT_SYMBOL_GPL(cec_transmit_msg);

static int cec_report_features(struct cec_adapter *adap, unsigned la_idx)
{
	struct cec_msg msg = { };
	u8 *features = adap->features[la_idx];
	bool op_is_dev_features = false;
	unsigned idx;

	if (adap->cec_version < CEC_OP_CEC_VERSION_2_0)
		return 0;

	/* Report Features */
	msg.msg[0] = (adap->log_addr[la_idx] << 4) | 0x0f;
	msg.len = 4;
	msg.msg[1] = CEC_MSG_REPORT_FEATURES;
	msg.msg[2] = adap->cec_version;
	msg.msg[3] = adap->all_device_types[la_idx];

	/* Write RC Profiles first, then Device Features */
	for (idx = 0; idx < sizeof(adap->features[0]); idx++) {
		msg.msg[msg.len++] = features[idx];
		if ((features[idx] & CEC_OP_FEAT_EXT) == 0) {
			if (op_is_dev_features)
				break;
			op_is_dev_features = true;
		}
	}
	return cec_transmit_msg(adap, &msg, false);
}

static int cec_report_phys_addr(struct cec_adapter *adap, unsigned la_idx)
{
	struct cec_msg msg = { };

	/* Report Physical Address */
	msg.msg[0] = (adap->log_addr[la_idx] << 4) | 0x0f;
	cec_msg_report_physical_addr(&msg, adap->phys_addr,
				     adap->prim_device[la_idx]);
	dprintk(2, "config: la %d pa %x.%x.%x.%x\n",
			adap->log_addr[la_idx],
			cec_phys_addr_exp(adap->phys_addr));
	return cec_transmit_msg(adap, &msg, false);
}

static int cec_feature_abort_reason(struct cec_adapter *adap,
				    struct cec_msg *msg, u8 reason)
{
	struct cec_msg tx_msg = { };

	/*
	 * Don't reply with CEC_MSG_FEATURE_ABORT to a CEC_MSG_FEATURE_ABORT
	 * message!
	 */
	if (msg->msg[1] == CEC_MSG_FEATURE_ABORT)
		return 0;
	cec_msg_set_reply_to(&tx_msg, msg);
	cec_msg_feature_abort(&tx_msg, msg->msg[1], reason);
	return cec_transmit_msg(adap, &tx_msg, false);
}

static int cec_feature_abort(struct cec_adapter *adap, struct cec_msg *msg)
{
	return cec_feature_abort_reason(adap, msg,
					CEC_OP_ABORT_UNRECOGNIZED_OP);
}

static int cec_feature_refused(struct cec_adapter *adap, struct cec_msg *msg)
{
	return cec_feature_abort_reason(adap, msg,
					CEC_OP_ABORT_REFUSED);
}

/*
 * Called when a CEC message is received. This function will do any
 * necessary core processing. The is_reply bool is true if this message
 * is a reply to an earlier transmit.
 */
static int cec_receive_notify(struct cec_adapter *adap, struct cec_msg *msg,
			      bool is_reply)
{
	bool is_broadcast = cec_msg_is_broadcast(msg);
	u8 dest_laddr = cec_msg_destination(msg);
	u8 init_laddr = cec_msg_initiator(msg);
	u8 devtype = cec_log_addr2dev(adap, dest_laddr);
	int la_idx = cec_log_addr2idx(adap, dest_laddr);
	bool is_directed = la_idx >= 0;
	bool from_unregistered = init_laddr == 0xf;
	u16 cdc_phys_addr;
	struct cec_msg tx_cec_msg = { };
	u8 *tx_msg = tx_cec_msg.msg;

	dprintk(1, "cec_receive_notify: %02x %02x\n", msg->msg[0], msg->msg[1]);

	if (!is_directed && !is_broadcast) {
		if (adap->passthrough)
			goto skip_processing;
		return 0;
	}

	if (adap->ops->received) {
		/* Allow drivers to process the message first */
		if (adap->ops->received(adap, msg) != -ENOMSG)
			return 0;
	}

	/*
	 * ARC, CDC and REPORT_PHYSICAL_ADDR, CEC_MSG_USER_CONTROL_PRESSED and
	 * CEC_MSG_USER_CONTROL_RELEASED messages always have to be
	 * handled by the CEC core, even if the passthrough mode is on.
	 * ARC and CDC messages will never be seen even if passthrough is
	 * on, but the others are just passed on normally.
	 */
	switch (msg->msg[1]) {
	case CEC_MSG_INITIATE_ARC:
	case CEC_MSG_TERMINATE_ARC:
	case CEC_MSG_REQUEST_ARC_INITIATION:
	case CEC_MSG_REQUEST_ARC_TERMINATION:
	case CEC_MSG_REPORT_ARC_INITIATED:
	case CEC_MSG_REPORT_ARC_TERMINATED:
		/* ARC messages are never passed through if CAP_ARC is set */

		/* Abort/ignore if ARC is not supported */
		if (!(adap->capabilities & CEC_CAP_ARC)) {
			/* Just abort if nobody is listening */
			if (is_directed && !is_reply && !adap->cec_owner)
				return cec_feature_abort(adap, msg);
			goto skip_processing;
		}
		/* Ignore if addressing is wrong */
		if (is_broadcast || from_unregistered)
			return 0;
		break;

	case CEC_MSG_CDC_MESSAGE:
		switch (msg->msg[4]) {
		case CEC_MSG_CDC_HPD_REPORT_STATE:
		case CEC_MSG_CDC_HPD_SET_STATE:
			/*
			 * CDC_HPD messages are never passed through if
			 * CAP_CDC_HPD is set
			 */

			/* Ignore if CDC_HPD is not supported */
			if (!(adap->capabilities & CEC_CAP_CDC_HPD))
				goto skip_processing;
			/* or the addressing is wrong */
			if (!is_broadcast)
				return 0;
			break;
		default:
			/* Other CDC messages are ignored */
			goto skip_processing;
		}
		break;

	case CEC_MSG_GET_CEC_VERSION:
	case CEC_MSG_GIVE_DEVICE_VENDOR_ID:
	case CEC_MSG_ABORT:
	case CEC_MSG_GIVE_DEVICE_POWER_STATUS:
	case CEC_MSG_GIVE_PHYSICAL_ADDR:
	case CEC_MSG_GIVE_OSD_NAME:
	case CEC_MSG_GIVE_FEATURES:
		/*
		 * Skip processing these messages if the passthrough mode
		 * is on.
		 */
		if (adap->passthrough)
			goto skip_processing;
		/* Ignore if addressing is wrong */
		if (is_broadcast || from_unregistered)
			return 0;
		break;

	case CEC_MSG_USER_CONTROL_PRESSED:
	case CEC_MSG_USER_CONTROL_RELEASED:
		/* Wrong addressing mode: don't process */
		if (is_broadcast || from_unregistered)
			goto skip_processing;
		break;

	case CEC_MSG_REPORT_PHYSICAL_ADDR:
		/*
		 * This message is always processed, regardless of the
		 * passthrough setting.
		 *
		 * Exception: don't process if wrong addressing mode.
		 */
		if (!is_broadcast)
			goto skip_processing;
		break;

	default:
		break;
	}

	cec_msg_set_reply_to(&tx_cec_msg, msg);

	switch (msg->msg[1]) {
	/* The following messages are processed but still passed through */
	case CEC_MSG_REPORT_PHYSICAL_ADDR:
		adap->phys_addrs[init_laddr] =
			(msg->msg[2] << 8) | msg->msg[3];
		dprintk(1, "Reported physical address %04x for logical address %d\n",
			adap->phys_addrs[init_laddr], init_laddr);
		break;

	case CEC_MSG_USER_CONTROL_PRESSED:
		if (!(adap->capabilities & CEC_CAP_RC))
			break;

		switch (msg->msg[2]) {
		/* Play function, this message can have variable length
		 * depending on the specific play function that is used.
		 */
		case 0x60:
			if (msg->len == 2)
				rc_keydown(adap->rc, RC_TYPE_CEC,
					   msg->msg[2], 0);
			else
				rc_keydown(adap->rc, RC_TYPE_CEC,
					   msg->msg[2] << 8 | msg->msg[3], 0);
			break;
		/* Other function messages that are not handled.
		 * Currently the RC framework does not allow to supply an
		 * additional parameter to a keypress. These "keys" contain
		 * other information such as channel number, an input number
		 * etc.
		 * For the time being these messages are not processed by the
		 * framework and are simply forwarded to the user space.
		 */
		case 0x56: case 0x57:
		case 0x67: case 0x68: case 0x69: case 0x6a:
			break;
		default:
			rc_keydown(adap->rc, RC_TYPE_CEC, msg->msg[2], 0);
			break;
		}
		break;

	case CEC_MSG_USER_CONTROL_RELEASED:
		if (!(adap->capabilities & CEC_CAP_RC))
			break;
		rc_keyup(adap->rc);
		break;

	/*
	 * The remaining messages are only processed if the passthrough mode
	 * is off.
	 */
	case CEC_MSG_GET_CEC_VERSION:
		cec_msg_cec_version(&tx_cec_msg, adap->cec_version);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_GIVE_PHYSICAL_ADDR:
		/* Do nothing for CEC switches using addr 15 */
		if (devtype == CEC_OP_PRIM_DEVTYPE_SWITCH && dest_laddr == 15)
			return 0;
		cec_msg_report_physical_addr(&tx_cec_msg, adap->phys_addr, devtype);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_GIVE_DEVICE_VENDOR_ID:
		if (!(adap->capabilities & CEC_CAP_VENDOR_ID) ||
		    adap->vendor_id == CEC_VENDOR_ID_NONE)
			return cec_feature_abort(adap, msg);
		cec_msg_device_vendor_id(&tx_cec_msg, adap->vendor_id);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_ABORT:
		/* Do nothing for CEC switches */
		if (devtype == CEC_OP_PRIM_DEVTYPE_SWITCH)
			return 0;
		return cec_feature_refused(adap, msg);

	case CEC_MSG_GIVE_DEVICE_POWER_STATUS:
		/* Do nothing for CEC switches */
		if (devtype == CEC_OP_PRIM_DEVTYPE_SWITCH)
			return 0;
		cec_msg_report_power_status(&tx_cec_msg, adap->pwr_state);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_GIVE_OSD_NAME: {
		if (adap->osd_name[0] == 0)
			return cec_feature_abort(adap, msg);
		cec_msg_set_osd_name(&tx_cec_msg, adap->osd_name);
		return cec_transmit_msg(adap, &tx_cec_msg, false);
	}

	case CEC_MSG_GIVE_FEATURES:
		if (adap->cec_version >= CEC_OP_CEC_VERSION_2_0)
			return cec_report_features(adap, la_idx);
		return 0;

	case CEC_MSG_REQUEST_ARC_INITIATION:
		if (!adap->is_source ||
		    !cec_la_are_adjacent(adap, dest_laddr, init_laddr))
			return cec_feature_refused(adap, msg);
		cec_msg_initiate_arc(&tx_cec_msg, false);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_REQUEST_ARC_TERMINATION:
		if (!adap->is_source ||
		    !cec_la_are_adjacent(adap, dest_laddr, init_laddr))
			return cec_feature_refused(adap, msg);
		cec_msg_terminate_arc(&tx_cec_msg, false);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_INITIATE_ARC:
		if (!adap->ninputs ||
		    !cec_la_are_adjacent(adap, dest_laddr, init_laddr))
			return cec_feature_refused(adap, msg);
		if (adap->ops->sink_initiate_arc && adap->ops->sink_initiate_arc(adap))
			return 0;
		cec_msg_report_arc_initiated(&tx_cec_msg);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_TERMINATE_ARC:
		if (!adap->ninputs ||
		    !cec_la_are_adjacent(adap, dest_laddr, init_laddr))
			return cec_feature_refused(adap, msg);
		if (adap->ops->sink_terminate_arc && adap->ops->sink_terminate_arc(adap))
			return 0;
		cec_msg_report_arc_terminated(&tx_cec_msg);
		return cec_transmit_msg(adap, &tx_cec_msg, false);

	case CEC_MSG_REPORT_ARC_INITIATED:
		if (!adap->is_source ||
		    !cec_la_are_adjacent(adap, dest_laddr, init_laddr))
			return cec_feature_refused(adap, msg);
		if (adap->ops->source_arc_initiated)
			adap->ops->source_arc_initiated(adap);
		return 0;

	case CEC_MSG_REPORT_ARC_TERMINATED:
		if (!adap->is_source ||
		    !cec_la_are_adjacent(adap, dest_laddr, init_laddr))
			return cec_feature_refused(adap, msg);
		if (adap->ops->source_arc_terminated)
			adap->ops->source_arc_terminated(adap);
		return 0;

	case CEC_MSG_CDC_MESSAGE: {
		unsigned shift;
		unsigned input_port;

		cdc_phys_addr = (msg->msg[2] << 8) | msg->msg[3];
		if (!cec_pa_are_adjacent(adap, cdc_phys_addr, adap->phys_addr))
			return 0;

		switch (msg->msg[4]) {
		case CEC_MSG_CDC_HPD_REPORT_STATE:
			/*
			 * Ignore if we're not a sink or the message comes from
			 * an upstream device.
			 */
			if (!adap->ninputs || cdc_phys_addr <= adap->phys_addr)
				return 0;
			adap->ops->sink_cdc_hpd(adap, msg->msg[5] >> 4, msg->msg[5] & 0xf);
			return 0;
		case CEC_MSG_CDC_HPD_SET_STATE:
			/* Ignore if we're not a source */
			if (!adap->is_source)
				return 0;
			break;
		default:
			return 0;
		}

		input_port = msg->msg[5] >> 4;
		for (shift = 0; shift < 16; shift += 4) {
			if (cdc_phys_addr & (0xf000 >> shift))
				continue;
			cdc_phys_addr |= input_port << (12 - shift);
			break;
		}
		if (cdc_phys_addr != adap->phys_addr)
			return 0;

		tx_cec_msg.len = 6;
		/* broadcast reply */
		tx_msg[0] = (adap->log_addr[0] << 4) | 0xf;
		cec_msg_cdc_hpd_report_state(&tx_cec_msg,
			     msg->msg[5] & 0xf,
			     adap->ops->source_cdc_hpd(adap, msg->msg[5] & 0xf));
		return cec_transmit_msg(adap, &tx_cec_msg, false);
	}

	default:
		/*
		 * Unprocessed messages are aborted if userspace isn't doing
		 * any processing either.
		 */
		if (is_directed && !is_reply && !adap->cec_owner)
			return cec_feature_abort(adap, msg);
		break;
	}

skip_processing:
	if (!is_reply && adap->cec_owner)
		cec_queue_msg_fh(adap->cec_owner, msg);
	return 0;
}

void cec_received_msg(struct cec_adapter *adap, struct cec_msg *msg)
{
	struct cec_data *data;
	bool is_reply = false;

	mutex_lock(&adap->lock);
	msg->ts = ktime_get_ns();
	msg->status = CEC_RX_STATUS_READY;
	msg->sequence = msg->reply = msg->timeout = 0;
	memset(msg->reserved, 0, sizeof(msg->reserved));
	dprintk(2, "cec_received_msg: %02x %02x\n", msg->msg[0], msg->msg[1]);
	if (msg->len > 1 && msg->msg[1] != CEC_MSG_CDC_MESSAGE) {
		u8 cmd = msg->msg[1];

		if (cmd == CEC_MSG_FEATURE_ABORT)
			cmd = msg->msg[2];
		list_for_each_entry(data, &adap->wait_queue, list) {
			struct cec_msg *dst = &data->msg;

			if (cec_msg_initiator(msg) != cec_msg_destination(dst) ||
			    cmd != dst->reply)
				continue;
			msg->sequence = dst->sequence;
			*dst = *msg;
			if (msg->msg[1] == CEC_MSG_FEATURE_ABORT) {
				dst->reply = 0;
				dst->status = CEC_TX_STATUS_FEATURE_ABORT;
			}
			list_del_init(&data->list);
			if (!cancel_delayed_work(&data->work)) {
				mutex_unlock(&adap->lock);
				flush_scheduled_work();
				mutex_lock(&adap->lock);
			}
			if (data->blocking || data->fh)
				is_reply = true;
			cec_data_completed(data);
			break;
		}
	}
	mutex_unlock(&adap->lock);
	cec_queue_msg_monitor(adap, msg);

	if (msg->len <= 1)
		return;

	cec_receive_notify(adap, msg, is_reply);
}
EXPORT_SYMBOL_GPL(cec_received_msg);

static int cec_receive_msg(struct cec_fh *fh, struct cec_msg *msg, bool block)
{
	int res;

	do {
		mutex_lock(&fh->lock);
		if (fh->queued_msgs) {
			struct cec_msg_entry *entry =
				list_first_entry(&fh->msgs,
						 struct cec_msg_entry, list);

			list_del(&entry->list);
			*msg = entry->msg;
			kfree(entry);
			fh->queued_msgs--;
			res = 0;
		} else {
			res = -EAGAIN;
		}
		mutex_unlock(&fh->lock);
		if (!block || !res)
			break;
		if (msg->timeout) {
			res = wait_event_interruptible_timeout(fh->wait,
				fh->queued_msgs,
				msecs_to_jiffies(msg->timeout));
			if (res == 0)
				res = -ETIMEDOUT;
			else if (res > 0)
				res = 0;
		} else {
			res = wait_event_interruptible(fh->wait,
				fh->queued_msgs);
		}
	} while (!res);
	return res;
}

static void cec_post_inputs_event_fh(struct cec_adapter *adap,
				     struct cec_fh *fh, u64 ts)
{
	struct cec_event *ev = &fh->events[CEC_EVENT_INPUTS_CHANGE - 1];
	struct cec_event_inputs_change *ch = &ev->inputs_change;

	mutex_lock(&fh->lock);
	if (ev->event == 0) {
		ev->ts = ts;
		ev->event = CEC_EVENT_INPUTS_CHANGE;
	}
	ch->changed_inputs |=
		adap->connected_inputs ^ ch->connected_inputs;
	ch->connected_inputs = adap->connected_inputs;
	mutex_unlock(&fh->lock);
	wake_up_interruptible(&fh->wait);
}

static void cec_post_inputs_event(struct cec_adapter *adap)
{
	u64 ts = ktime_get_ns();
	struct cec_fh *fh;

	mutex_lock(&adap->devnode.fhs_lock);
	list_for_each_entry(fh, &adap->devnode.fhs, list)
		cec_post_inputs_event_fh(adap, fh, ts);
	mutex_unlock(&adap->devnode.fhs_lock);
}

int cec_enable(struct cec_adapter *adap, bool enable)
{
	int ret = 0;

	mutex_lock(&adap->lock);
	if (enable == adap->is_enabled)
		goto unlock;
	ret = adap->ops->adap_enable(adap, enable);
	if (ret)
		goto unlock;
	adap->is_configured = false;
	adap->is_enabled = enable;
	if (!enable) {
		adap->num_log_addrs = 0;
		memset(adap->phys_addrs, 0xff, sizeof(adap->phys_addrs));
		wake_up_interruptible(&adap->kthread_waitq);
	}
	cec_post_state_event(adap);
unlock:
	mutex_unlock(&adap->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(cec_enable);

struct cec_log_addrs_int {
	struct cec_adapter *adap;
	struct cec_log_addrs log_addrs;
	struct completion c;
	bool free_on_exit;
	int err;
};

static int cec_config_log_addrs(struct cec_adapter *adap,
				struct cec_log_addrs *log_addrs)
{
	static const u8 tv_log_addrs[] = {
		0, CEC_LOG_ADDR_INVALID
	};
	static const u8 record_log_addrs[] = {
		1, 2, 9, 12, 13, CEC_LOG_ADDR_INVALID
	};
	static const u8 tuner_log_addrs[] = {
		3, 6, 7, 10, 12, 13, CEC_LOG_ADDR_INVALID
	};
	static const u8 playback_log_addrs[] = {
		4, 8, 11, 12, 13, CEC_LOG_ADDR_INVALID
	};
	static const u8 audiosystem_log_addrs[] = {
		5, 12, 13, CEC_LOG_ADDR_INVALID
	};
	static const u8 specific_use_log_addrs[] = {
		14, 12, 13, CEC_LOG_ADDR_INVALID
	};
	static const u8 unregistered_log_addrs[] = {
		CEC_LOG_ADDR_INVALID
	};
	static const u8 *type2addrs[7] = {
		[CEC_LOG_ADDR_TYPE_TV] = tv_log_addrs,
		[CEC_LOG_ADDR_TYPE_RECORD] = record_log_addrs,
		[CEC_LOG_ADDR_TYPE_TUNER] = tuner_log_addrs,
		[CEC_LOG_ADDR_TYPE_PLAYBACK] = playback_log_addrs,
		[CEC_LOG_ADDR_TYPE_AUDIOSYSTEM] = audiosystem_log_addrs,
		[CEC_LOG_ADDR_TYPE_SPECIFIC] = specific_use_log_addrs,
		[CEC_LOG_ADDR_TYPE_UNREGISTERED] = unregistered_log_addrs,
	};
	struct cec_msg msg = { };
	u32 claimed_addrs = 0;
	int i, j;
	int err;

	if (adap->phys_addr) {
		/* The TV functionality can only map to physical address 0.
		   For any other address, try the Specific functionality
		   instead as per the spec. */
		for (i = 0; i < log_addrs->num_log_addrs; i++)
			if (log_addrs->log_addr_type[i] == CEC_LOG_ADDR_TYPE_TV)
				log_addrs->log_addr_type[i] =
						CEC_LOG_ADDR_TYPE_SPECIFIC;
	}

	dprintk(2, "physical address: %x.%x.%x.%x, claim %d logical addresses\n",
			cec_phys_addr_exp(adap->phys_addr),
			log_addrs->num_log_addrs);
	strlcpy(adap->osd_name, log_addrs->osd_name, sizeof(adap->osd_name));
	adap->num_log_addrs = 0;
	cec_post_state_event(adap);

	/* TODO: remember last used logical addr type to achieve
	   faster logical address polling by trying that one first.
	 */
	for (i = 0; i < log_addrs->num_log_addrs; i++) {
		const u8 *la_list = type2addrs[log_addrs->log_addr_type[i]];

		if (kthread_should_stop()) {
			err = -EINTR;
			goto unconfigure;
		}

		for (j = 0; la_list[j] != CEC_LOG_ADDR_INVALID; j++) {
			u8 log_addr = la_list[j];

			if (claimed_addrs & (1 << log_addr))
				continue;

			/* Send polling message */
			msg.len = 1;
			msg.msg[0] = 0xf0 | log_addr;
			msg.reply = 0;
			err = cec_transmit_msg(adap, &msg, true);
			if (err)
				goto unconfigure;

			if (msg.status == CEC_TX_STATUS_RETRY_TIMEOUT) {
				unsigned idx = adap->num_log_addrs++;

				/* Message not acknowledged, so this logical
				   address is free to use. */
				claimed_addrs |= 1 << log_addr;
				adap->log_addr[idx] = log_addr;
				log_addrs->log_addr[i] = log_addr;
				adap->log_addr_type[idx] =
					log_addrs->log_addr_type[i];
				adap->prim_device[idx] =
					log_addrs->primary_device_type[i];
				adap->all_device_types[idx] =
					log_addrs->all_device_types[i];
				adap->phys_addrs[log_addr] = adap->phys_addr;
				memcpy(adap->features[idx], log_addrs->features[i],
				       sizeof(adap->features[idx]));
				err = adap->ops->adap_log_addr(adap, log_addr);
				dprintk(2, "claim addr %d (%d)\n", log_addr,
							adap->prim_device[idx]);
				if (err)
					goto unconfigure;

				/*
				 * Report Features must come first according
				 * to CEC 2.0
				 */
				cec_report_features(adap, idx);
				cec_report_phys_addr(adap, idx);
				break;
			}
		}
	}
	if (adap->num_log_addrs == 0) {
		if (log_addrs->num_log_addrs > 1)
			dprintk(2, "could not claim last %d addresses\n",
				log_addrs->num_log_addrs - 1);
		adap->log_addr[0] = 15;
		adap->log_addr_type[0] = CEC_LOG_ADDR_TYPE_UNREGISTERED;
		adap->prim_device[0] = CEC_OP_PRIM_DEVTYPE_SWITCH;
		adap->all_device_types[0] = CEC_OP_ALL_DEVTYPE_SWITCH;
		err = adap->ops->adap_log_addr(adap, 15);
		dprintk(2, "claim addr %d (%d)\n", 15, adap->prim_device[0]);
		if (err)
			goto unconfigure;

		adap->num_log_addrs = 1;
		/* TODO: do we need to do this for an unregistered device? */
		cec_report_phys_addr(adap, 0);
	}
	mutex_lock(&adap->lock);
	adap->is_configured = true;
	adap->is_configuring = false;
	cec_post_state_event(adap);
	mutex_unlock(&adap->lock);
	return 0;

unconfigure:
	mutex_lock(&adap->lock);
	adap->num_log_addrs = 0;
	adap->is_configuring = false;
	cec_post_state_event(adap);
	mutex_unlock(&adap->lock);
	return err;
}

static int cec_config_thread_func(void *arg)
{
	struct cec_log_addrs_int *cla_int = arg;
	int err;

	cla_int->err = err = cec_config_log_addrs(cla_int->adap,
						  &cla_int->log_addrs);
	cla_int->adap->kthread_config = NULL;
	if (cla_int->free_on_exit)
		kfree(cla_int);
	else
		complete(&cla_int->c);

	return err;
}

int cec_claim_log_addrs(struct cec_adapter *adap,
			struct cec_log_addrs *log_addrs, bool block)
{
	struct cec_log_addrs_int *cla_int;
	int i;

	if (!adap->is_enabled)
		return -ENONET;

	if (log_addrs->num_log_addrs > CEC_MAX_LOG_ADDRS) {
		dprintk(1, "num_log_addrs > %d\n", CEC_MAX_LOG_ADDRS);
		return -EINVAL;
	}
	if (log_addrs->num_log_addrs == 0) {
		int err = adap->ops->adap_log_addr(adap, CEC_LOG_ADDR_INVALID);

		if (err)
			return err;
		mutex_lock(&adap->lock);
		adap->is_configured = false;
		adap->num_log_addrs = 0;
		wake_up_interruptible(&adap->kthread_waitq);
		cec_post_state_event(adap);
		mutex_unlock(&adap->lock);
		return 0;
	}
	if (log_addrs->cec_version != CEC_OP_CEC_VERSION_1_4 &&
	    log_addrs->cec_version != CEC_OP_CEC_VERSION_2_0) {
		dprintk(1, "unsupported CEC version\n");
		return -EINVAL;
	}
	if (log_addrs->num_log_addrs > 1)
		for (i = 0; i < log_addrs->num_log_addrs; i++)
			if (log_addrs->log_addr_type[i] ==
					CEC_LOG_ADDR_TYPE_UNREGISTERED) {
				dprintk(1, "can't claim unregistered logical address\n");
				return -EINVAL;
			}
	for (i = 0; i < log_addrs->num_log_addrs; i++) {
		u8 *features = log_addrs->features[i];
		bool op_is_dev_features = false;

		if (log_addrs->primary_device_type[i] >
					CEC_OP_PRIM_DEVTYPE_PROCESSOR) {
			dprintk(1, "unknown primary device type\n");
			return -EINVAL;
		}
		if (log_addrs->primary_device_type[i] == 2) {
			dprintk(1, "invalid primary device type\n");
			return -EINVAL;
		}
		if (log_addrs->log_addr_type[i] > CEC_LOG_ADDR_TYPE_UNREGISTERED) {
			dprintk(1, "unknown logical address type\n");
			return -EINVAL;
		}
		if (log_addrs->cec_version < CEC_OP_CEC_VERSION_2_0)
			continue;

		for (i = 0; i < sizeof(adap->features[0]); i++) {
			if ((features[i] & 0x80) == 0) {
				if (op_is_dev_features)
					break;
				op_is_dev_features = true;
			}
		}
		if (!op_is_dev_features || i == sizeof(adap->features[0])) {
			dprintk(1, "malformed features\n");
			return -EINVAL;
		}
	}

	/* For phys addr 0xffff only the Unregistered functionality is
	   allowed. */
	if (adap->phys_addr == CEC_PHYS_ADDR_INVALID &&
	    (log_addrs->num_log_addrs > 1 ||
	     log_addrs->log_addr_type[0] != CEC_LOG_ADDR_TYPE_UNREGISTERED)) {
		dprintk(1, "physical addr 0xffff only allows unregistered logical address\n");
		return -EINVAL;
	}

	cla_int = kzalloc(sizeof(*cla_int), GFP_KERNEL);
	if (cla_int == NULL)
		return -ENOMEM;
	mutex_lock(&adap->lock);
	if (adap->is_configuring || adap->is_configured) {
		mutex_unlock(&adap->lock);
		kfree(cla_int);
		return -EBUSY;
	}
	adap->is_configuring = true;
	mutex_unlock(&adap->lock);
	init_completion(&cla_int->c);
	cla_int->free_on_exit = !block;
	cla_int->adap = adap;
	cla_int->log_addrs = *log_addrs;
	adap->kthread_config = kthread_run(cec_config_thread_func, cla_int,
					   "ceccfg-%s", adap->name);
	if (block) {
		wait_for_completion(&cla_int->c);
		*log_addrs = cla_int->log_addrs;
		kfree(cla_int);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(cec_claim_log_addrs);

void cec_log_status(struct cec_adapter *adap)
{
	dprintk(0, "enabled: %d\n", adap->is_enabled);
	dprintk(0, "configured: %d\n", adap->is_configured);
	dprintk(0, "configuring: %d\n", adap->is_configuring);
	dprintk(0, "phys_addr: %04x\n", adap->phys_addr);
	dprintk(0, "number of LAs: %d\n", adap->num_log_addrs);
	if (adap->cec_owner)
		dprintk(0, "has owner\n");
	if (adap->passthrough)
		dprintk(0, "has passthrough\n");
	if (mutex_is_locked(&adap->lock))
		dprintk(0, "is locked\n");
}
EXPORT_SYMBOL_GPL(cec_log_status);

void cec_connected_inputs(struct cec_adapter *adap, u16 connected_inputs)
{
	if (adap->connected_inputs != connected_inputs) {
		adap->connected_inputs = connected_inputs;
		if (!adap->devnode.dead)
			cec_post_inputs_event(adap);
	}
}
EXPORT_SYMBOL_GPL(cec_connected_inputs);

u8 cec_sink_cdc_hpd(struct cec_adapter *adap, u8 input_port, u8 cdc_hpd_state)
{
	struct cec_msg msg = { };
	int err;

	if (!adap->is_configured)
		return CEC_OP_HPD_ERROR_INITIATOR_WRONG_STATE;

	msg.msg[0] = (adap->log_addr[0] << 4) | 0xf;
	cec_msg_cdc_hpd_set_state(&msg, input_port, cdc_hpd_state);
	err = cec_transmit_msg(adap, &msg, false);
	if (err)
		return CEC_OP_HPD_ERROR_OTHER;
	return CEC_OP_HPD_ERROR_NONE;
}
EXPORT_SYMBOL_GPL(cec_sink_cdc_hpd);

static unsigned int cec_poll(struct file *filp,
			       struct poll_table_struct *poll)
{
	struct cec_devnode *devnode = cec_devnode_data(filp);
	struct cec_fh *fh = filp->private_data;
	struct cec_adapter *adap = fh->adap;
	unsigned res = 0;

	if (devnode->dead)
		return POLLERR | POLLHUP;
	mutex_lock(&adap->lock);
	if (adap->is_configured)
		res |= POLLOUT | POLLWRNORM;
	if (fh->queued_msgs)
		res |= POLLIN | POLLRDNORM;
	if (fh->events)
		res |= POLLPRI;
	poll_wait(filp, &fh->wait, poll);
	mutex_unlock(&adap->lock);
	return res;
}

static long cec_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct cec_devnode *devnode = cec_devnode_data(filp);
	struct cec_fh *fh = filp->private_data;
	struct cec_adapter *adap = fh->adap;
	bool block = !(filp->f_flags & O_NONBLOCK);
	void __user *parg = (void __user *)arg;
	int err;

	if (devnode->dead)
		return -EIO;

	switch (cmd) {
	case CEC_ADAP_G_CAPS: {
		struct cec_caps caps;

		caps.available_log_addrs = adap->available_log_addrs;
		caps.capabilities = adap->capabilities;
		caps.ninputs = adap->ninputs;
		memset(caps.reserved, 0, sizeof(caps.reserved));
		if (copy_to_user(parg, &caps, sizeof(caps)))
			return -EFAULT;
		break;
	}

	case CEC_TRANSMIT: {
		struct cec_msg msg;

		if (!(adap->capabilities & CEC_CAP_IO))
			return -ENOTTY;
		if (copy_from_user(&msg, parg, sizeof(msg)))
			return -EFAULT;
		memset(msg.reserved, 0, sizeof(msg.reserved));
		if (!adap->is_configured)
			return -ENONET;
		if (fh->monitor)
			return -EPERM;
		if (adap->cec_owner && adap->cec_owner != fh)
			return -EBUSY;
		if (block || !msg.reply)
			fh = NULL;

		err = cec_transmit_msg_fh(adap, &msg, fh, block);
		if (err)
			return err;
		if (copy_to_user(parg, &msg, sizeof(msg)))
			return -EFAULT;
		break;
	}

	case CEC_RECEIVE: {
		struct cec_msg msg;

		if (!(adap->capabilities & CEC_CAP_IO))
			return -ENOTTY;
		if (copy_from_user(&msg, parg, sizeof(msg)))
			return -EFAULT;
		memset(msg.reserved, 0, sizeof(msg.reserved));
		if (!adap->is_configured)
			return -ENONET;
		if (!fh->monitor && adap->cec_owner != fh)
			return -EPERM;

		err = cec_receive_msg(fh, &msg, block);
		if (err)
			return err;
		if (copy_to_user(parg, &msg, sizeof(msg)))
			return -EFAULT;
		break;
	}

	case CEC_DQEVENT: {
		struct cec_event *ev = NULL;
		u64 ts = ~0ULL;
		unsigned i;

		mutex_lock(&fh->lock);
		for (i = 0; i < CEC_NUM_EVENTS; i++) {
			if (fh->events[i].event &&
			    fh->events[i].ts <= ts) {
				ev = &fh->events[i];
				ts = ev->ts;
			}
		}
		err = -EAGAIN;
		if (ev) {
			if (copy_to_user((void __user *)arg, ev, sizeof(*ev))) {
				err = -EFAULT;
			} else {
				if (ev->event == CEC_EVENT_INPUTS_CHANGE)
					ev->inputs_change.changed_inputs = 0;
				ev->event = 0;
				err = 0;
			}
		}
		mutex_unlock(&fh->lock);
		return err;
	}

	case CEC_ADAP_G_STATE: {
		u32 state = adap->is_enabled;

		if (copy_to_user(parg, &state, sizeof(state)))
			return -EFAULT;
		break;
	}

	case CEC_ADAP_S_STATE: {
		u32 state;

		if (!(adap->capabilities & CEC_CAP_STATE))
			return -ENOTTY;
		if (copy_from_user(&state, parg, sizeof(state)))
			return -EFAULT;
		if (state > CEC_ADAP_ENABLED)
			return -EINVAL;
		if (adap->is_configuring)
			return -EBUSY;
		if (state == adap->is_enabled)
			return 0;
		if (adap->cec_owner && adap->cec_owner != fh)
			return -EBUSY;
		cec_enable(adap, state);
		break;
	}

	case CEC_ADAP_G_PHYS_ADDR: {
		u16 phys_addr = adap->is_enabled ? adap->phys_addr :
			CEC_PHYS_ADDR_INVALID;

		if (copy_to_user(parg, &phys_addr, sizeof(adap->phys_addr)))
			return -EFAULT;
		break;
	}

	case CEC_ADAP_S_PHYS_ADDR: {
		u16 phys_addr;

		if (!(adap->capabilities & CEC_CAP_PHYS_ADDR))
			return -ENOTTY;
		if (copy_from_user(&phys_addr, parg, sizeof(phys_addr)))
			return -EFAULT;
		if (adap->phys_addr == phys_addr)
			return 0;
		if (!adap->is_enabled)
			return -ENONET;
		if (adap->is_configuring || adap->is_configured)
			return -EBUSY;
		if (adap->cec_owner && adap->cec_owner != fh)
			return -EBUSY;
		adap->phys_addr = phys_addr;
		break;
	}

	case CEC_ADAP_S_LOG_ADDRS: {
		struct cec_log_addrs log_addrs;

		if (!(adap->capabilities & CEC_CAP_LOG_ADDRS))
			return -ENOTTY;
		if (copy_from_user(&log_addrs, parg, sizeof(log_addrs)))
			return -EFAULT;
		if (adap->is_configuring)
			return -EBUSY;
		if (log_addrs.num_log_addrs && adap->is_configured)
			return -EBUSY;
		if (adap->cec_owner && adap->cec_owner != fh)
			return -EBUSY;

		memset(log_addrs.reserved, 0, sizeof(log_addrs.reserved));
		err = cec_claim_log_addrs(adap, &log_addrs, block);
		if (err)
			return err;

		if (filp->f_flags & O_NONBLOCK) {
			if (copy_to_user(parg, &log_addrs, sizeof(log_addrs)))
				return -EFAULT;
			break;
		}

		/* fall through */
	}

	case CEC_ADAP_G_LOG_ADDRS: {
		struct cec_log_addrs log_addrs = { adap->cec_version };
		unsigned i;

		mutex_lock(&adap->lock);
		log_addrs.num_log_addrs = adap->num_log_addrs;
		strlcpy(log_addrs.osd_name, adap->osd_name,
			sizeof(log_addrs.osd_name));
		for (i = 0; i < adap->num_log_addrs; i++) {
			log_addrs.primary_device_type[i] = adap->prim_device[i];
			log_addrs.log_addr_type[i] = adap->log_addr_type[i];
			log_addrs.log_addr[i] = adap->log_addr[i];
			log_addrs.all_device_types[i] = adap->all_device_types[i];
			memcpy(log_addrs.features[i], adap->features[i],
			       sizeof(log_addrs.features[i]));
		}
		mutex_unlock(&adap->lock);

		if (copy_to_user(parg, &log_addrs, sizeof(log_addrs)))
			return -EFAULT;
		break;
	}

	case CEC_ADAP_G_VENDOR_ID:
		if (copy_to_user(parg, &adap->vendor_id,
						sizeof(adap->vendor_id)))
			return -EFAULT;
		break;

	case CEC_ADAP_S_VENDOR_ID: {
		u32 vendor_id;

		if (!(adap->capabilities & CEC_CAP_VENDOR_ID))
			return -ENOTTY;
		if (copy_from_user(&vendor_id, parg, sizeof(vendor_id)))
			return -EFAULT;
		/* Vendor ID is a 24 bit number, so check if the value is
		 * within the correct range. */
		if (vendor_id != CEC_VENDOR_ID_NONE &&
		    (vendor_id & 0xff000000) != 0)
			return -EINVAL;
		if (adap->vendor_id == vendor_id)
			return 0;
		if (adap->is_configuring || adap->is_configured)
			return -EBUSY;
		if (adap->cec_owner && adap->cec_owner != fh)
			return -EBUSY;
		adap->vendor_id = vendor_id;
		break;
	}

	case CEC_G_PASSTHROUGH: {
		u32 passthrough = CEC_PASSTHROUGH_DISABLED;

		if (!(adap->capabilities & CEC_CAP_PASSTHROUGH))
			return -ENOTTY;
		if (adap->cec_owner == fh)
			passthrough = adap->passthrough;
		if (copy_to_user(parg, &passthrough, sizeof(passthrough)))
			return -EFAULT;
		break;
	}

	case CEC_G_MONITOR: {
		u32 monitor = fh->monitor;

		if (copy_to_user(parg, &monitor, sizeof(monitor)))
			return -EFAULT;
		break;
	}

	case CEC_S_MONITOR: {
		u32 monitor;

		if (copy_from_user(&monitor, parg, sizeof(monitor)))
			return -EFAULT;
		if (monitor > CEC_MONITOR_ENABLED)
			return -EINVAL;
		if (fh->monitor == monitor)
			break;
		if (adap->cec_owner == fh)
			return -EBUSY;
		fh->monitor = monitor;
		break;
	}

	case CEC_CLAIM: {
		u32 passthrough;

		if (copy_from_user(&passthrough, parg, sizeof(passthrough)))
			return -EFAULT;
		if (passthrough > CEC_PASSTHROUGH_ENABLED)
			return -EINVAL;
		if (passthrough &&
		    !(adap->capabilities & CEC_CAP_PASSTHROUGH))
			return -EPERM;
		if (adap->cec_owner && adap->cec_owner != fh)
			return -EBUSY;
		if (fh->monitor)
			return -EBUSY;
		mutex_lock(&adap->lock);
		adap->passthrough = passthrough;
		adap->cec_owner = fh;
		mutex_unlock(&adap->lock);
		break;
	}

	case CEC_RELEASE: {
		if (adap->cec_owner && adap->cec_owner != fh)
			return -EBUSY;
		mutex_lock(&adap->lock);
		adap->cec_owner = NULL;
		adap->passthrough = 0;
		mutex_unlock(&adap->lock);
		break;
	}

	default:
		return -ENOTTY;
	}
	return 0;
}

/* Override for the open function */
static int cec_open(struct inode *inode, struct file *filp)
{
	struct cec_devnode *devnode;
	struct cec_fh *fh = kzalloc(sizeof(*fh), GFP_KERNEL);

	if (fh == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&fh->msgs);
	mutex_init(&fh->lock);
	init_waitqueue_head(&fh->wait);

	/* Check if the cec device is available. This needs to be done with
	 * the cec_devnode_lock held to prevent an open/unregister race:
	 * without the lock, the device could be unregistered and freed between
	 * the devnode->dead check and get_device() calls, leading to
	 * a crash.
	 */
	mutex_lock(&cec_devnode_lock);
	devnode = container_of(inode->i_cdev, struct cec_devnode, cdev);
	/* return ENXIO if the cec device has been removed
	   already or if it is not registered anymore. */
	if (devnode->dead) {
		mutex_unlock(&cec_devnode_lock);
		kfree(fh);
		return -ENXIO;
	}
	/* and increase the device refcount */
	get_device(&devnode->dev);
	mutex_unlock(&cec_devnode_lock);

	fh->adap = to_cec_adapter(devnode);
	filp->private_data = fh;
	mutex_lock(&devnode->fhs_lock);
	list_add(&fh->list, &devnode->fhs);
	mutex_unlock(&devnode->fhs_lock);
	if (fh->adap->ninputs)
		cec_post_inputs_event_fh(fh->adap, fh, ktime_get_ns());
	cec_post_state_event_fh(fh->adap, fh, ktime_get_ns());

	return 0;
}

/* Override for the release function */
static int cec_release(struct inode *inode, struct file *filp)
{
	struct cec_devnode *devnode = cec_devnode_data(filp);
	struct cec_adapter *adap = to_cec_adapter(devnode);
	struct cec_fh *fh = filp->private_data;
	int ret = 0;

	if (adap->cec_owner == fh)
		adap->cec_owner = NULL;

	mutex_lock(&devnode->fhs_lock);
	list_del(&fh->list);
	mutex_unlock(&devnode->fhs_lock);

	while (!list_empty(&fh->msgs)) {
		struct cec_msg_entry *entry =
			list_first_entry(&fh->msgs, struct cec_msg_entry, list);

		list_del(&entry->list);
		kfree(entry);
	}
	kfree(fh);

	/* decrease the refcount unconditionally since the release()
	   return value is ignored. */
	put_device(&devnode->dev);
	filp->private_data = NULL;
	return ret;
}

static const struct file_operations cec_devnode_fops = {
	.owner = THIS_MODULE,
	.open = cec_open,
	.unlocked_ioctl = cec_ioctl,
	.release = cec_release,
	.poll = cec_poll,
	.llseek = no_llseek,
};

/* Called when the last user of the cec device exits. */
static void cec_devnode_release(struct device *cd)
{
	struct cec_devnode *devnode = to_cec_devnode(cd);

	mutex_lock(&cec_devnode_lock);

	/* Mark device node number as free */
	clear_bit(devnode->minor, cec_devnode_nums);

	mutex_unlock(&cec_devnode_lock);
	kfree(to_cec_adapter(devnode));
}

static struct bus_type cec_bus_type = {
	.name = CEC_NAME,
};

/**
 * cec_devnode_register - register a cec device node
 * @devnode: cec device node structure we want to register
 *
 * The registration code assigns minor numbers and registers the new device node
 * with the kernel. An error is returned if no free minor number can be found,
 * or if the registration of the device node fails.
 *
 * Zero is returned on success.
 *
 * Note that if the cec_devnode_register call fails, the release() callback of
 * the cec_devnode structure is *not* called, so the caller is responsible for
 * freeing any data.
 */
static int __must_check cec_devnode_register(struct cec_devnode *devnode,
		struct module *owner)
{
	int minor;
	int ret;

	/* Initialization */
	INIT_LIST_HEAD(&devnode->fhs);
	mutex_init(&devnode->fhs_lock);

	/* Part 1: Find a free minor number */
	mutex_lock(&cec_devnode_lock);
	minor = find_next_zero_bit(cec_devnode_nums, CEC_NUM_DEVICES, 0);
	if (minor == CEC_NUM_DEVICES) {
		mutex_unlock(&cec_devnode_lock);
		pr_err("could not get a free minor\n");
		return -ENFILE;
	}

	set_bit(minor, cec_devnode_nums);
	mutex_unlock(&cec_devnode_lock);

	devnode->minor = minor;
	devnode->dev.bus = &cec_bus_type;
	devnode->dev.devt = MKDEV(MAJOR(cec_dev_t), minor);
	devnode->dev.release = cec_devnode_release;
	devnode->dev.parent = devnode->parent;
	dev_set_name(&devnode->dev, "cec%d", devnode->minor);
	device_initialize(&devnode->dev);

	/* Part 2: Initialize and register the character device */
	cdev_init(&devnode->cdev, &cec_devnode_fops);
	devnode->cdev.kobj.parent = &devnode->dev.kobj;
	devnode->cdev.owner = owner;

	ret = cdev_add(&devnode->cdev, devnode->dev.devt, 1);
	if (ret < 0) {
		pr_err("%s: cdev_add failed\n", __func__);
		goto clr_bit;
	}

	ret = device_add(&devnode->dev);
	if (ret)
		goto cdev_del;

	return 0;

cdev_del:
	cdev_del(&devnode->cdev);
clr_bit:
	clear_bit(devnode->minor, cec_devnode_nums);
	put_device(&devnode->dev);
	return ret;
}

/**
 * cec_devnode_unregister - unregister a cec device node
 * @devnode: the device node to unregister
 *
 * This unregisters the passed device. Future open calls will be met with
 * errors.
 *
 * This function can safely be called if the device node has never been
 * registered or has already been unregistered.
 */
static void cec_devnode_unregister(struct cec_devnode *devnode)
{
	struct cec_fh *fh;

	/* Check if devnode was already unregistered */
	if (WARN_ON(devnode->dead))
		return;

	mutex_lock(&devnode->fhs_lock);
	list_for_each_entry(fh, &devnode->fhs, list)
		wake_up_interruptible(&fh->wait);
	mutex_unlock(&devnode->fhs_lock);

	devnode->dead = true;
	device_del(&devnode->dev);
	cdev_del(&devnode->cdev);
	put_device(&devnode->dev);
}

struct cec_adapter *cec_create_adapter(const struct cec_adap_ops *ops,
		       void *priv, const char *name, u32 caps,
		       u8 ninputs, struct module *owner, struct device *parent)
{
	struct cec_adapter *adap;
	int res;

	if (WARN_ON(!owner))
		return ERR_PTR(-EINVAL);
	if (WARN_ON(!parent))
		return ERR_PTR(-EINVAL);
	if (WARN_ON(!ninputs && !(caps & CEC_CAP_IS_SOURCE)))
		return ERR_PTR(-EINVAL);
	if (WARN_ON(!caps))
		return ERR_PTR(-EINVAL);
	if (WARN_ON(!ops))
		return ERR_PTR(-EINVAL);
	adap = kzalloc(sizeof(*adap), GFP_KERNEL);
	if (adap == NULL)
		return ERR_PTR(-ENOMEM);
	adap->owner = owner;
	adap->devnode.parent = parent;
	adap->name = name;
	adap->phys_addr = CEC_PHYS_ADDR_INVALID;
	adap->capabilities = caps;
	adap->ninputs = ninputs;
	adap->is_source = caps & CEC_CAP_IS_SOURCE;
	adap->cec_version = CEC_OP_CEC_VERSION_2_0;
	adap->vendor_id = CEC_VENDOR_ID_NONE;
	adap->available_log_addrs = 1;
	adap->sequence = 0;
	adap->ops = ops;
	adap->priv = priv;
	memset(adap->phys_addrs, 0xff, sizeof(adap->phys_addrs));
	mutex_init(&adap->lock);
	INIT_LIST_HEAD(&adap->transmit_queue);
	INIT_LIST_HEAD(&adap->wait_queue);
	init_waitqueue_head(&adap->kthread_waitq);

	adap->kthread = kthread_run(cec_thread_func, adap, "cec-%s", name);
	if (IS_ERR(adap->kthread)) {
		pr_err("cec-%s: kernel_thread() failed\n", name);
		res = PTR_ERR(adap->kthread);
		kfree(adap);
		return ERR_PTR(res);
	}
	res = cec_devnode_register(&adap->devnode, adap->owner);
	if (res) {
		kthread_stop(adap->kthread);
		kfree(adap);
		return ERR_PTR(res);
	}

	if (!(caps & CEC_CAP_RC))
		return adap;

	/* Prepare the RC input device */
	adap->rc = rc_allocate_device();
	if (!adap->rc) {
		pr_err("cec-%s: failed to allocate memory for rc_dev\n",
		       name);
		res = -ENOMEM;
		goto fail;
	}

	snprintf(adap->input_name, sizeof(adap->input_name),
		 "RC for %s", name);
	snprintf(adap->input_phys, sizeof(adap->input_phys),
		 "%s/input0", name);
	strlcpy(adap->input_drv, name, sizeof(adap->input_drv));

	adap->rc->input_name = adap->input_name;
	adap->rc->input_phys = adap->input_phys;
	adap->rc->input_id.bustype = BUS_CEC;
	adap->rc->input_id.vendor = 0;
	adap->rc->input_id.product = 0;
	adap->rc->input_id.version = 1;
	adap->rc->dev.parent = parent;
	adap->rc->driver_name = adap->input_drv;
	adap->rc->driver_type = RC_DRIVER_CEC;
	adap->rc->allowed_protocols = RC_BIT_CEC;
	adap->rc->priv = adap;
	adap->rc->map_name = RC_MAP_CEC;
	adap->rc->timeout = MS_TO_NS(100);

	res = rc_register_device(adap->rc);

	if (res) {
		pr_err("cec-%s: failed to prepare input device\n",
		       name);
		rc_free_device(adap->rc);
		goto fail;
	}

	return adap;

fail:
	kthread_stop(adap->kthread);
	cec_devnode_unregister(&adap->devnode);
	return ERR_PTR(res);
}
EXPORT_SYMBOL_GPL(cec_create_adapter);

void cec_delete_adapter(struct cec_adapter *adap)
{
	if (IS_ERR_OR_NULL(adap))
		return;
	kthread_stop(adap->kthread);
	if (adap->kthread_config)
		kthread_stop(adap->kthread_config);
	if (adap->is_enabled)
		cec_enable(adap, false);
	rc_unregister_device(adap->rc);
	cec_devnode_unregister(&adap->devnode);
}
EXPORT_SYMBOL_GPL(cec_delete_adapter);

/*
 *	Initialise cec for linux
 */
static int __init cec_devnode_init(void)
{
	int ret;

	pr_info("Linux cec interface: v0.10\n");
	ret = alloc_chrdev_region(&cec_dev_t, 0, CEC_NUM_DEVICES,
				  CEC_NAME);
	if (ret < 0) {
		pr_warn("cec: unable to allocate major\n");
		return ret;
	}

	ret = bus_register(&cec_bus_type);
	if (ret < 0) {
		unregister_chrdev_region(cec_dev_t, CEC_NUM_DEVICES);
		pr_warn("cec: bus_register failed\n");
		return -EIO;
	}

	return 0;
}

static void __exit cec_devnode_exit(void)
{
	bus_unregister(&cec_bus_type);
	unregister_chrdev_region(cec_dev_t, CEC_NUM_DEVICES);
}

subsys_initcall(cec_devnode_init);
module_exit(cec_devnode_exit)

MODULE_AUTHOR("Hans Verkuil <hans.verkuil@cisco.com>");
MODULE_DESCRIPTION("Device node registration for cec drivers");
MODULE_LICENSE("GPL");
