// #include <linux/bpf.h>
// #include <linux/btf.h>
// #include <linux/jhash.h>
// #include <linux/filter.h>
// #include <linux/rculist_nulls.h>
// #include <linux/random.h>
// #include <uapi/linux/btf.h>
// #include <linux/rcupdate_trace.h>
// #include <linux/btf_ids.h>


// struct bpf_rbtree {
//     struct bpf_map map;
// };

// static bool rbtree_map_meta_equal(const struct bpf_map *meta0,
// 				 const struct bpf_map *meta1)
// {
// 	if (!bpf_map_meta_equal(meta0, meta1))
// 		return false;
// 	return meta0->map_flags & BPF_F_INNER_MAP ? true :
// 	       meta0->max_entries == meta1->max_entries;
// }


// const struct bpf_map_ops rbtree_map_ops = {
// 	.map_meta_equal = rbtree_map_meta_equal,
// 	.map_alloc_check = array_map_alloc_check,
// 	.map_alloc = array_map_alloc,
// 	.map_free = array_map_free,
// 	.map_get_next_key = array_map_get_next_key,
// 	.map_release_uref = array_map_free_timers,
// 	.map_lookup_elem = array_map_lookup_elem,
// 	.map_update_elem = array_map_update_elem,
// 	.map_delete_elem = array_map_delete_elem,
// 	.map_gen_lookup = array_map_gen_lookup,
// 	.map_direct_value_addr = array_map_direct_value_addr,
// 	.map_direct_value_meta = array_map_direct_value_meta,
// 	.map_mmap = array_map_mmap,
// 	.map_seq_show_elem = array_map_seq_show_elem,
// 	.map_check_btf = array_map_check_btf,
// 	.map_lookup_batch = generic_map_lookup_batch,
// 	.map_update_batch = generic_map_update_batch,
// 	.map_set_for_each_callback_args = map_set_for_each_callback_args,
// 	.map_for_each_callback = bpf_for_each_array_elem,
// 	.map_btf_id = &array_map_btf_ids[0],
// 	.iter_seq_info = &iter_seq_info,
// };