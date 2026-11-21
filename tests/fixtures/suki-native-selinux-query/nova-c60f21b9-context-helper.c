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
                                  &context, &orig_context, orig_policy->latest_granting, def_sid, &orig_rc);
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
