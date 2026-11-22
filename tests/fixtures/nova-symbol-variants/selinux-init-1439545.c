static int selinux_hide_init_setxattr()
{
    int ret;

    ret = ksu_selinux_superblock_init();
    if (ret)
        return ret;

    inode_doinit_with_dentry_fn = ksu_resolve_symbol_for_functable_hook("inode_doinit_with_dentry");
    // Set original before publishing callback to other CPUs
    selinux_inode_setxattr_hook.original = ksu_resolve_symbol_for_functable_hook("selinux_inode_setxattr");
    if (!inode_doinit_with_dentry_fn || !selinux_inode_setxattr_hook.original)
        return -ENOENT;
    return 0;
}
