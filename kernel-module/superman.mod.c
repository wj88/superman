#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x1fc32c62, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x6a4bf290, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x5ccc8e71, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0xb9ede69a, __VMLINUX_SYMBOL_STR(genl_unregister_family) },
	{ 0x46adf3d, __VMLINUX_SYMBOL_STR(single_release) },
	{ 0xc01cf848, __VMLINUX_SYMBOL_STR(_raw_read_lock) },
	{ 0xc0b059c, __VMLINUX_SYMBOL_STR(icmp_send) },
	{ 0x2124474, __VMLINUX_SYMBOL_STR(ip_send_check) },
	{ 0xa05f372e, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0x12d54a2b, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0xf32055e7, __VMLINUX_SYMBOL_STR(dev_base_lock) },
	{ 0x608abff8, __VMLINUX_SYMBOL_STR(__genl_register_family) },
	{ 0xef197d66, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x9ca10237, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0xb53c57d9, __VMLINUX_SYMBOL_STR(proc_mkdir) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x1f1b453e, __VMLINUX_SYMBOL_STR(inet_select_addr) },
	{ 0xf6c79f47, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0x7e3d544, __VMLINUX_SYMBOL_STR(ip_route_me_harder) },
	{ 0x7ca37acc, __VMLINUX_SYMBOL_STR(dev_get_by_index) },
	{ 0x62878c7b, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xd6e506b5, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xc6206c6b, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x1a236d64, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xf4ee8424, __VMLINUX_SYMBOL_STR(ip_route_output_flow) },
	{ 0xf6ebc03b, __VMLINUX_SYMBOL_STR(net_ratelimit) },
	{ 0x5c3edd59, __VMLINUX_SYMBOL_STR(_raw_write_unlock_bh) },
	{ 0xa877ee10, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0xc68122ec, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0x6916acf6, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0xfdee7d42, __VMLINUX_SYMBOL_STR(_raw_read_lock_bh) },
	{ 0xf37260ab, __VMLINUX_SYMBOL_STR(_raw_read_unlock_bh) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x32eeaded, __VMLINUX_SYMBOL_STR(_raw_write_lock_bh) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "C162D0787DD5FBFCF1489C9");
