#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define DEVICE_NAME "if_mirror_char" ///< The device will appear at /dev/if_mirror_char using this value
#define CLASS_NAME "ifm" ///< The device class -- this is a character device driver
#define ROUTE_ALL 0
#define COMMAND_DEL ';'

// Netfilter info
typedef struct {
	char iface_in_name[16];
	char iface_out_name[16];
	char listen_protocol[16];
	char ip[32];
	int gateway_ip;
	char protocol_type;
} s_interface_info;

s_interface_info *interface_info = {0};

struct socket *tcp_sock;
struct socket *udp_sock;
static struct net_device *gw_net_dev;
static struct net *net;
static struct nf_hook_ops nfho; // struct holding set of hook function options
// Device driver info
static int majorNumber;		  ///< Stores the device number -- determined automatically
static char message[256] = {0};   ///< Memory for the string that is passed from userspace
static short size_of_message;     ///< Used to remember the size of the string stored
static int device_open_count = 0; ///< Counts the number of times the device is opened
static struct class *if_mirror_charClass = NULL;   ///< The device-driver class struct pointer
static struct device *if_mirror_charDevice = NULL; ///< The device-driver device struct pointer
int dev_reader_flag = 0;
static int num_of_usr_req = 0;
static DECLARE_WAIT_QUEUE_HEAD(readers_wait_q);

// The prototype functions for the character driver -- must come before the struct definition
static int device_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
    .open = device_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};

static int device_open(struct inode *inodep, struct file *filep)
{
	/* If device is open, return busy */
	if (device_open_count) {
		return -EBUSY;
	}
	device_open_count++;
	try_module_get(THIS_MODULE);
	pr_info("IF_MIRRORChar: Device has been opened \n");
	return 0;
}

static int parse_inargs(void)
{
	int protocol_len = sizeof("udp"); // same as tcp
	int i;
	for (i = 0; i < num_of_usr_req; i++) {
		if (interface_info[i].iface_in_name == NULL ||
		    interface_info[i].iface_out_name == NULL ||
		    interface_info[i].listen_protocol == NULL || interface_info[i].ip == NULL ||
		    strlen(interface_info[i].ip) > 16)
			return EINVAL;

		if (!strncmp(interface_info[i].listen_protocol, "udp", protocol_len) ||
		    !strncmp(interface_info[i].listen_protocol, "UDP", protocol_len))
			interface_info[i].protocol_type = IPPROTO_UDP;
		else if (!strncmp(interface_info[i].listen_protocol, "tcp", protocol_len) ||
			 !strncmp(interface_info[i].listen_protocol, "TCP", protocol_len))
			interface_info[i].protocol_type = IPPROTO_TCP;
		else if (!strncmp(interface_info[i].listen_protocol, "all", protocol_len) ||
			 !strncmp(interface_info[i].listen_protocol, "ALL", protocol_len))
			interface_info[i].protocol_type = ROUTE_ALL;
		interface_info[i].gateway_ip = in_aton(interface_info[i].ip);
	}

	return 0;
}

static char *strtok(char *str, const char *delim)
{
	static char *_buffer;
	char *ret, *b;
	const char *d;

	if (str != NULL)
		_buffer = str;
	if (_buffer[0] == '\0')
		return NULL;

	ret = _buffer;

	for (b = _buffer; *b != '\0'; b++) {
		for (d = delim; *d != '\0'; d++) {
			if (*b == *d) {
				*b = '\0';
				_buffer = b + 1;

				// skip the beginning delimiters
				if (b == ret) {
					ret++;
					continue;
				}
				return ret;
			}
		}
	}

	return ret;
}
static void parse_msg_in(char *message, size_t len)
{
	int i;
	char *token;

	for (i = 0; i < len; i++) {
		if (message[i] == COMMAND_DEL)
			num_of_usr_req++;
	}
	i = 0;

	pr_info("IF_MIRRORChar: Msg from user is:\n");
	interface_info = kmalloc_array(num_of_usr_req, sizeof(s_interface_info), GFP_KERNEL);
	token = strtok(message, ";");
	while (token) {
		sscanf(token, "%s %s %s %s", interface_info[i].iface_in_name,
		       interface_info[i].iface_out_name, interface_info[i].listen_protocol,
		       interface_info[i].ip);
		pr_info("iface_in_name=%s, iface_out_name=%s, listen_protocol=%s, ip=%s\n",
			interface_info[i].iface_in_name, interface_info[i].iface_out_name,
			interface_info[i].listen_protocol, interface_info[i].ip);
		i++;
		token = strtok(NULL, ";");
	}
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user.
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
	int error_count = 0;

	pr_info(KERN_DEBUG "process %i (%s) going to sleep\n", current->pid, current->comm);
	wait_event_interruptible(readers_wait_q, dev_reader_flag != 0);
	dev_reader_flag = 0;
	pr_info(KERN_DEBUG "awoken %i (%s)\n", current->pid, current->comm);
	// copy_to_user has the format ( * to, *from, size) and returns 0 on success
	error_count = copy_to_user(buffer, message, size_of_message);
	if (error_count == 0) { // success!
		pr_info("IF_MIRRORChar: Sent %d characters to the user\n", size_of_message);

		return (size_of_message = 0); // clear the position to the start and return 0
	} else {
		pr_info("IF_MIRRORChar: Failed to send %d characters to the user\n", error_count);
		return -EFAULT; // Failed -- return a bad address message (i.e. -14)
	}
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
	if (copy_from_user(message, buffer, len)) // appending received string with its length
	{
		return -EFAULT;
	}
	message[len] = '\0';

	parse_msg_in(message, len);
	size_of_message = len;

	pr_info("IF_MIRRORChar: End of user msg ==> which is %zu characters long\n", len);
	if (parse_inargs())
		dev_reader_flag = -1;
	else
		dev_reader_flag = 1;
	wake_up_interruptible(&readers_wait_q);
	return len;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
	device_open_count--;
	module_put(THIS_MODULE);
	pr_info("IF_MIRRORChar: Device successfully closed\n");
	return 0;
}

static int __init if_mirror_char_init(void)
{
	pr_info("IF_MIRRORChar: Initializing the if_mirror_char LKM\n");

	// Try to dynamically allocate a major number for the device -- more difficult but worth it
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber < 0) {
		pr_alert("if_mirror_char failed to register a major number\n");
		return majorNumber;
	}
	pr_info("IF_MIRRORChar: registered correctly with major number %d\n", majorNumber);

	// Register the device class
	if_mirror_charClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(if_mirror_charClass)) { // Check for error and clean up if there is
		unregister_chrdev(majorNumber, DEVICE_NAME);
		pr_alert("Failed to register device class\n");
		return PTR_ERR(if_mirror_charClass); // Correct way to return an error on a pointer
	}
	pr_info("IF_MIRRORChar: device class registered correctly\n");

	// Register the device driver
	if_mirror_charDevice =
	    device_create(if_mirror_charClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(if_mirror_charDevice)) { // Clean up if there is an error
		class_destroy(
		    if_mirror_charClass); // Repeated code but the alternative is goto statements
		unregister_chrdev(majorNumber, DEVICE_NAME);
		pr_alert("Failed to create the device\n");
		return PTR_ERR(if_mirror_charDevice);
	}

	init_waitqueue_head(&readers_wait_q);

	pr_info(
	    "IF_MIRRORChar: device class created correctly\n"); // Made it! device was initialized
	return 0;
}

static void if_mirror_char_exit(void)
{
	device_destroy(if_mirror_charClass, MKDEV(majorNumber, 0)); // remove the device
	class_unregister(if_mirror_charClass);			    // unregister the device class
	class_destroy(if_mirror_charClass);			    // remove the device class
	unregister_chrdev(majorNumber, DEVICE_NAME);		    // unregister the major number
	pr_info("IF_MIRRORChar: Goodbye from the LKM!\n");
}


// function to be called by hook
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); // you can access to IP source and dest - ip_header->saddr, ip_header->daddr
	struct ethhdr *eth = eth_hdr(skb);
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	static struct net_device *switched_device = NULL;
	unsigned char *tail = 0;
	unsigned char *data;
	int packet_len = 0;
	int i;
	bool bEnter_mirroring = false;
	pr_debug("Mac address = %pM\n", eth->h_source);
	pr_debug("IP addres = %pI4\n", &ip_header->saddr);

	for (i = 0; i < num_of_usr_req; i++) {
		if (interface_info[i].gateway_ip == ip_header->saddr &&
		    (ip_header->protocol == interface_info[i].protocol_type ||
		     interface_info[i].protocol_type == ROUTE_ALL)) {
			bEnter_mirroring = true;
			break;
		}
	}

	if (bEnter_mirroring) {
		bEnter_mirroring = false;
		switch (ip_header->protocol) {
		case IPPROTO_ICMP: {
			pr_info("ICMP Packet\n");
			break;
		}
		case IPPROTO_TCP: {
			pr_info("TCP Packet\n");
			tcp_header = tcp_hdr(skb);
			pr_debug("Source Port: %u\n",
				 tcp_header->source); // can access dest in the same way
			pr_debug("Dest Port: %u\n", tcp_header->dest);
			data = (unsigned char *)((char *)tcp_header + tcp_header->doff * 4);
			tail = skb_tail_pointer(skb);
			packet_len = (int)((long)tail - (long)data);
			pr_info("packet len:%d\n", packet_len);
			break;
		}
		case IPPROTO_UDP: {
			pr_info("UDP Packet\n");
			udp_header = udp_hdr(skb);
			pr_debug("Source Port: %u\n",
				 udp_header->source); // can access dest in the same way
			pr_debug("Dest Port: %u\n", udp_header->dest);
			data = ((char *)udp_header + sizeof(struct udphdr));
			packet_len = ntohs(udp_header->len) - sizeof(struct udphdr);
			pr_info("packet len:%d\n", packet_len);
			break;
		}
		default:
			break;
		}

		// if (packet_len)//sanity check
		{
			int ret;
			struct ethhdr *mirror_header;

			switched_device =
			    dev_get_by_name(&init_net, interface_info[i].iface_out_name);
			if (!switched_device) {
				pr_emerg("Error: Netfilter couldn't find %s device.\n",
					 interface_info[i].iface_out_name);
				return -EINVAL;
			}

			mirror_header = (struct ethhdr *)skb_push(skb, ETH_HLEN);

			skb->protocol = mirror_header->h_proto = htons(ETH_P_IP);
			skb->dev = switched_device;
			pr_info("Found device %s\n", switched_device->name);

			/*changing Mac address */
			pr_info("source MAC: %pM\n", mirror_header->h_source);
			memcpy(mirror_header->h_dest, switched_device->dev_addr, ETH_ALEN);
			pr_info("Dest MAC: %pM\n", mirror_header->h_dest);
			/* send the packet */
			ret = dev_queue_xmit(skb);
			printk(KERN_DEBUG "\ndev_queue_xmit returned %d\n", ret);
			// read_unlock(&dev_base_lock);
			return NF_STOLEN;
		}
	}
	return NF_ACCEPT;
}

// Called when module loaded using 'insmod'
static int __init net_init_module(void)
{
	if_mirror_char_init();
	pr_info(KERN_DEBUG "process %i (%s) going to sleep on init_module\n", current->pid,
		current->comm);
	wait_event_interruptible(readers_wait_q, dev_reader_flag != 0);
	if (dev_reader_flag == -1) {
		pr_emerg("Error:  bad parameter for char device\n");
		return -EINVAL;
	}
	pr_debug("awoken init_module%i (%s)\n", current->pid, current->comm);
	pr_info("init\n");

	gw_net_dev = dev_get_by_name(
	    &init_net,
	    interface_info[0]
		.iface_in_name); // We assume all source interfaces are the same interface
	if (gw_net_dev == NULL) {
		pr_emerg("Error: Netfilter received bad module parameter: %s\n",
			 interface_info[0].iface_in_name);
		return -EINVAL;
	}
	net = dev_net(gw_net_dev);

	nfho.hook = hook_func; // function to call when conditions below met
	nfho.hooknum =
	    NF_INET_PRE_ROUTING; // called right after packet recieved, first hook in Netfilter
	nfho.pf = PF_INET;       // IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST; // set to highest priority over all other hook functions

	nf_register_net_hook(net, &nfho); // register hook
	pr_info("Register hook done\n");

	return 0; // return 0 for success
}

// Called when module unloaded using 'rmmod'
static void __exit net_cleanup_module(void)
{
	if_mirror_char_exit();
	kfree(interface_info);
	nf_unregister_net_hook(net, &nfho); // cleanup – unregister hook
	pr_info("Un Register hook done\n");
}

module_init(net_init_module);
module_exit(net_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Elad Hazan");
MODULE_DESCRIPTION("Interface Mirroring");