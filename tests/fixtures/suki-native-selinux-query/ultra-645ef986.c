#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define ksu_avc_has_perm_compat(...) avc_has_perm(__VA_ARGS__)
#else
#define ksu_avc_has_perm_compat(...) avc_has_perm(&selinux_state, __VA_ARGS__)
#endif

static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
    // apply to all app uids
    if (likely(current_uid().val < 10000)) {
        return orig_context_write(file, buf, size);
    }
    char *canon = NULL;
    u32 sid, len;
    ssize_t length;

    length =
        ksu_avc_has_perm_compat(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
    if (length)
        goto out;
    length = security_context_to_sid_with_policy(backup_sepolicy, buf, size, &sid, SECSID_NULL, GFP_KERNEL, NULL, NULL);
    if (length) {
        goto out;
    }

    length = security_sid_to_context_with_policy(backup_sepolicy, sid, &canon, &len);
    if (length)
        goto out;

    length = -ERANGE;
    if (len > SIMPLE_TRANSACTION_LIMIT) {
        pr_err("SELinux: %s:  context size (%u) exceeds "
               "payload max\n",
               __func__, len);
        goto out;
    }

    memcpy(buf, canon, len);
    length = len;
out:
    kfree(canon);
    return length;
}

static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    // apply to all app uids
    if (likely(current_uid().val < 10000)) {
        return orig_access_write(file, buf, size);
    }
    char *scon = NULL, *tcon = NULL;
    u32 ssid, tsid, sconlen, tconlen;
    u16 tclass;
    struct av_decision avd;
    ssize_t length;

    length = ksu_avc_has_perm_compat(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
    if (length)
        goto out;

    length = -ENOMEM;
    scon = kzalloc(size + 1, GFP_KERNEL);
    if (!scon)
        goto out;

    length = -ENOMEM;
    tcon = kzalloc(size + 1, GFP_KERNEL);
    if (!tcon)
        goto out;

    length = -EINVAL;
    if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
        goto out;

    sconlen = strlen(scon);
    tconlen = strlen(tcon);

    length =
        security_context_to_sid_with_policy(backup_sepolicy, scon, sconlen, &ssid, SECSID_NULL, GFP_KERNEL, NULL, NULL);
    if (length) {
        goto out;
    }

    length =
        security_context_to_sid_with_policy(backup_sepolicy, tcon, tconlen, &tsid, SECSID_NULL, GFP_KERNEL, NULL, NULL);
    if (length) {
        goto out;
    }

    security_compute_av_user_with_policy(backup_sepolicy, ssid, tsid, tclass, &avd);

    // stock reads 1; a loader load_policy may have bumped the backup before we load
    avd.seqno = 1;
    length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x", avd.allowed, 0xffffffff, avd.auditallow,
                       avd.auditdeny, avd.seqno, avd.flags);
out:
    kfree(tcon);
    kfree(scon);
    return length;
}

static int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext, u32 scontext_len,
                                               u32 *sid, u32 def_sid, gfp_t gfp_flags, u32 *orig_sid_p, int *orig_rc_p)
{
    struct selinux_policy *orig_policy;
    struct policydb *policydb, *orig_policydb;
    struct sidtab *sidtab, *orig_sidtab;
    char *scontext2;
    struct context context, orig_context;
    int rc = 0, orig_rc = -EINVAL;
    u32 orig_sid;

    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

    /* Copy the string to allow changes and ensure a NUL terminator */
    scontext2 = kmemdup_nul(scontext, scontext_len, gfp_flags);
    if (!scontext2)
        return -ENOMEM;

    // removed: if (!selinux_initialized())
    *sid = SECSID_NULL;
    if (orig_sid_p)
        *orig_sid_p = SECSID_NULL;

    // removed: if (force)
retry:
    rcu_read_lock();
    policydb = &policy->policydb;
    sidtab = policy->sidtab;
    orig_policy = rcu_dereference(selinux_state.policy);
    orig_policydb = &orig_policy->policydb;
    orig_sidtab = orig_policy->sidtab;

    // parse both policies together
    orig_rc = -EINVAL;
    rc = string_to_context_struct(policydb, orig_policydb, sidtab, orig_sidtab, scontext2, scontext, scontext_len,
                                  &context, &orig_context, def_sid, &orig_rc);
    if (rc)
        goto out_unlock;

    // update backup sidtab first
    rc = sidtab_context_to_sid(sidtab, &context, sid);
    context_destroy(&context);
    if (rc) {
        if (!orig_rc)
            context_destroy(&orig_context);
        // backup sidtab is not reloaded
        orig_rc = rc;
        goto out_unlock;
    }

    if (orig_rc)
        goto out_unlock;

    // only sync valid contexts
    // sync to live sidtab
    orig_rc = sidtab_context_to_sid(orig_sidtab, &orig_context, &orig_sid);
    context_destroy(&orig_context);
    if (!orig_rc && orig_sid_p)
        *orig_sid_p = orig_sid;
    if (orig_rc == -ESTALE) {
        // retry after live policy reload
        rcu_read_unlock();
        memcpy(scontext2, scontext, scontext_len);
        scontext2[scontext_len] = '\0';
        goto retry;
    }
out_unlock:
    rcu_read_unlock();
    if (orig_rc_p)
        *orig_rc_p = orig_rc;
    kfree(scontext2);
    return rc;
}

static int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext,
                                               u32 *scontext_len)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct sidtab_entry *entry;
    int rc = 0;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    // removed: if (!selinux_initialized())
    // removed: rcu lock
    policydb = &policy->policydb;
    sidtab = policy->sidtab;

    // removed: force
    entry = sidtab_search_entry(sidtab, sid);
    if (!entry) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, sid);
        rc = -EINVAL;
        goto out_unlock;
    }
    // removed: only_invalid

    rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);

out_unlock:
    return rc;
}

static void __nocfi security_compute_av_user_with_policy(struct selinux_policy *policy, u32 ssid, u32 tsid, u16 tclass,
                                                         struct av_decision *avd)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct context *scontext = NULL, *tcontext = NULL;

    // remove: rcu lock
    avd_init(policy, avd);
    // remove: if (!selinux_initialized())

    policydb = &policy->policydb;
    sidtab = policy->sidtab;

    scontext = sidtab_search(sidtab, ssid);
    if (!scontext) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, ssid);
        goto out;
    }

    /* permissive domain? */
    if (ebitmap_get_bit(&policydb->permissive_map, scontext->type))
        avd->flags |= AVD_FLAGS_PERMISSIVE;

    tcontext = sidtab_search(sidtab, tsid);
    if (!tcontext) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, tsid);
        goto out;
    }

    if (unlikely(!tclass)) {
        if (policydb->allow_unknown)
            goto allow;
        goto out;
    }

    if (context_struct_compute_av_fn) {
        context_struct_compute_av_fn(policydb, scontext, tcontext, tclass, avd, NULL);
    } else {
        context_struct_compute_av(policydb, scontext, tcontext, tclass, avd, NULL);
    }
out:
    return;
allow:
    avd->allowed = 0xffffffff;
    goto out;
}
