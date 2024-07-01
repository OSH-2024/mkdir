static const struct bpf_func_proto bpf_get_func_ret_proto = {
	.func		= get_func_ret,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_LONG,
};

BPF_CALL_1(get_func_arg_cnt, void *, ctx)
{
	/* This helper call is inlined by verifier. */
	return ((u64 *)ctx)[-1];
}

static const struct bpf_func_proto bpf_get_func_arg_cnt_proto = {
	.func		= get_func_arg_cnt,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

#ifdef CONFIG_KEYS
__bpf_kfunc_start_defs();

/**
 * bpf_lookup_user_key - lookup a key by its serial
 * @serial: key handle serial number
 * @flags: lookup-specific flags
 *
 * Search a key with a given *serial* and the provided *flags*.
 * If found, increment the reference count of the key by one, and
 * return it in the bpf_key structure.
 *
 * The bpf_key structure must be passed to bpf_key_put() when done
 * with it, so that the key reference count is decremented and the
 * bpf_key structure is freed.
 *
 * Permission checks are deferred to the time the key is used by
 * one of the available key-specific kfuncs.
 *
 * Set *flags* with KEY_LOOKUP_CREATE, to attempt creating a requested
 * special keyring (e.g. session keyring), if it doesn't yet exist.
 * Set *flags* with KEY_LOOKUP_PARTIAL, to lookup a key without waiting
 * for the key construction, and to retrieve uninstantiated keys (keys
 * without data attached to them).
 *
 * Return: a bpf_key pointer with a valid key pointer if the key is found, a
 *         NULL pointer otherwise.
 */
__bpf_kfunc struct bpf_key *bpf_lookup_user_key(u32 serial, u64 flags)
{
	key_ref_t key_ref;
	struct bpf_key *bkey;

	if (flags & ~KEY_LOOKUP_ALL)
		return NULL;

	/*
	 * Permission check is deferred until the key is used, as the
	 * intent of the caller is unknown here.
	 */
	key_ref = lookup_user_key(serial, flags, KEY_DEFER_PERM_CHECK);
	if (IS_ERR(key_ref))
		return NULL;

	bkey = kmalloc(sizeof(*bkey), GFP_KERNEL);
	if (!bkey) {
		key_put(key_ref_to_ptr(key_ref));
		return NULL;
	}

	bkey->key = key_ref_to_ptr(key_ref);
	bkey->has_ref = true;

	return bkey;
}

/**
 * bpf_lookup_system_key - lookup a key by a system-defined ID
 * @id: key ID
 *
 * Obtain a bpf_key structure with a key pointer set to the passed key ID.
 * The key pointer is marked as invalid, to prevent bpf_key_put() from
 * attempting to decrement the key reference count on that pointer. The key
 * pointer set in such way is currently understood only by
 * verify_pkcs7_signature().
 *
 * Set *id* to one of the values defined in include/linux/verification.h:
 * 0 for the primary keyring (immutable keyring of system keys);
 * VERIFY_USE_SECONDARY_KEYRING for both the primary and secondary keyring
 * (where keys can be added only if they are vouched for by existing keys
 * in those keyrings); VERIFY_USE_PLATFORM_KEYRING for the platform
 * keyring (primarily used by the integrity subsystem to verify a kexec'ed
 * kerned image and, possibly, the initramfs signature).
 *
 * Return: a bpf_key pointer with an invalid key pointer set from the
 *         pre-determined ID on success, a NULL pointer otherwise
 */
__bpf_kfunc struct bpf_key *bpf_lookup_system_key(u64 id)
{
	struct bpf_key *bkey;

	if (system_keyring_id_check(id) < 0)
		return NULL;

	bkey = kmalloc(sizeof(*bkey), GFP_ATOMIC);
	if (!bkey)
		return NULL;

	bkey->key = (struct key *)(unsigned long)id;
	bkey->has_ref = false;

	return bkey;
}

/**
 * bpf_key_put - decrement key reference count if key is valid and free bpf_key
 * @bkey: bpf_key structure
 *
 * Decrement the reference count of the key inside *bkey*, if the pointer
 * is valid, and free *bkey*.
 */
__bpf_kfunc void bpf_key_put(struct bpf_key *bkey)
{
	if (bkey->has_ref)
		key_put(bkey->key);

	kfree(bkey);
}

#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
/**
 * bpf_verify_pkcs7_signature - verify a PKCS#7 signature
 * @data_ptr: data to verify
 * @sig_ptr: signature of the data
 * @trusted_keyring: keyring with keys trusted for signature verification
 *
 * Verify the PKCS#7 signature *sig_ptr* against the supplied *data_ptr*
 * with keys in a keyring referenced by *trusted_keyring*.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_verify_pkcs7_signature(struct bpf_dynptr_kern *data_ptr,
			       struct bpf_dynptr_kern *sig_ptr,
			       struct bpf_key *trusted_keyring)
{
	const void *data, *sig;
	u32 data_len, sig_len;
	int ret;

	if (trusted_keyring->has_ref) {
		/*
		 * Do the permission check deferred in bpf_lookup_user_key().
		 * See bpf_lookup_user_key() for more details.
		 *
		 * A call to key_task_permission() here would be redundant, as
		 * it is already done by keyring_search() called by
		 * find_asymmetric_key().
		 */
		ret = key_validate(trusted_keyring->key);
		if (ret < 0)
			return ret;
	}

	data_len = __bpf_dynptr_size(data_ptr);
	data = __bpf_dynptr_data(data_ptr, data_len);
	sig_len = __bpf_dynptr_size(sig_ptr);
	sig = __bpf_dynptr_data(sig_ptr, sig_len);

	return verify_pkcs7_signature(data, data_len, sig, sig_len,
				      trusted_keyring->key,
				      VERIFYING_UNSPECIFIED_SIGNATURE, NULL,
				      NULL);
}
#endif /* CONFIG_SYSTEM_DATA_VERIFICATION */

__bpf_kfunc_end_defs();

BTF_SET8_START(key_sig_kfunc_set)
BTF_ID_FLAGS(func, bpf_lookup_user_key, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_lookup_system_key, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_key_put, KF_RELEASE)
#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
BTF_ID_FLAGS(func, bpf_verify_pkcs7_signature, KF_SLEEPABLE)
#endif
BTF_SET8_END(key_sig_kfunc_set)

static const struct btf_kfunc_id_set bpf_key_sig_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &key_sig_kfunc_set,
};

static int __init bpf_key_sig_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					 &bpf_key_sig_kfunc_set);
}

late_initcall(bpf_key_sig_kfuncs_init);
#endif /* CONFIG_KEYS */

/* filesystem kfuncs */
__bpf_kfunc_start_defs();

/**
 * bpf_get_file_xattr - get xattr of a file
 * @file: file to get xattr from
 * @name__str: name of the xattr
 * @value_ptr: output buffer of the xattr value
 *
 * Get xattr *name__str* of *file* and store the output in *value_ptr*.
 *
 * For security reasons, only *name__str* with prefix "user." is allowed.
 *
 * Return: 0 on success, a negative value on error.
 */
__bpf_kfunc int bpf_get_file_xattr(struct file *file, const char *name__str,
				   struct bpf_dynptr_kern *value_ptr)
{
	struct dentry *dentry;
	u32 value_len;
	void *value;
	int ret;

	if (strncmp(name__str, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
		return -EPERM;

	value_len = __bpf_dynptr_size(value_ptr);
	value = __bpf_dynptr_data_rw(value_ptr, value_len);
	if (!value)
		return -EINVAL;

	dentry = file_dentry(file);
	ret = inode_permission(&nop_mnt_idmap, dentry->d_inode, MAY_READ);
	if (ret)
		return ret;
	return __vfs_getxattr(dentry, dentry->d_inode, name__str, value, value_len);
}

__bpf_kfunc_end_defs();

BTF_SET8_START(fs_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_get_file_xattr, KF_SLEEPABLE | KF_TRUSTED_ARGS)
BTF_SET8_END(fs_kfunc_set_ids)

static int bpf_get_file_xattr_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&fs_kfunc_set_ids, kfunc_id))
		return 0;

	/* Only allow to attach from LSM hooks, to avoid recursion */
	return prog->type != BPF_PROG_TYPE_LSM ? -EACCES : 0;
}

static const struct btf_kfunc_id_set bpf_fs_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &fs_kfunc_set_ids,
	.filter = bpf_get_file_xattr_filter,
};

static int __init bpf_fs_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_fs_kfunc_set);
}
late_initcall(bpf_fs_kfuncs_init);