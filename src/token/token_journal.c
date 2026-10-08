/**
 * @file token_journal.c
 * @brief Intent journal: power-loss-safe BIND, REBIND, RESET and POLICY.
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Journal (PROTOCOL.md §5) ───────────────────────────────────────── */

int journal_apply(void)
{
	qdsd_state_t *s = &g_tk.st;
	port_counter_t ctr = PORT_CTR_BINDING;
	uint8_t i;
	int rc;

	switch (s->j_op) {
	case J_NONE:
		return 0;
	case J_BIND:
	case J_REBIND:
		rc = port_pubkey_write(PORT_PUBKEY_ACTIVATION, s->j_key);
		if (rc != 0) {
			return rc;
		}
		break;
	case J_RESET:
		for (i = 0U; i < QDSD_DSC_SLOTS; i++) {
			if (!ok_or_absent(port_dsc_delete(i)) ||
			    (slot_certs_delete(i) != 0) ||
			    !ok_or_absent(port_obj_delete(PORT_OBJ_SLOT_REC, i))) {
				return -EIO;
			}
		}
		if ((rcpt_clear_all() != 0) ||
		    !ok_or_absent(port_pubkey_delete(PORT_PUBKEY_ACTIVATION))) {
			return -EIO;
		}
		break;
	case J_POLICY:
		ctr = PORT_CTR_POLICY;
		break;
	default:
		return -EBADMSG; /* J_WIPE is finished by FACTORY_WIPE, not here */
	}

	rc = counter_to(ctr, s->j_target);
	if (rc != 0) {
		return rc;
	}

	if ((s->j_op == J_BIND) || (s->j_op == J_POLICY)) {
		s->policy_flags = s->j_flags;
	} else if (s->j_op == J_RESET) {
		s->policy_flags = 0U;
	}
	s->lc = s->j_next_lc;
	s->j_op = J_NONE;
	s->j_next_lc = 0U;
	s->j_flags = 0U;
	s->j_target = 0U;
	secure_zero(s->j_key, sizeof(s->j_key));
	rc = state_save(s);
	if (rc == 0) {
		port_event(PORT_EVT_STATE_CHANGED, s->lc);
	}
	return rc;
}

/* Record intent, then apply. On failure the token goes FAULT until reboot. */
uint16_t journal_run(uint8_t op, uint32_t target, const uint8_t *key, uint8_t flags,
			    uint8_t next_lc)
{
	qdsd_state_t saved = g_tk.st;

	g_tk.st.j_op = op;
	g_tk.st.j_target = target;
	g_tk.st.j_flags = flags;
	g_tk.st.j_next_lc = next_lc;
	if (key != NULL) {
		memcpy(g_tk.st.j_key, key, sizeof(g_tk.st.j_key));
	} else {
		memset(g_tk.st.j_key, 0, sizeof(g_tk.st.j_key));
	}

	if (state_save(&g_tk.st) != 0) {
		g_tk.st = saved;
		return SW_INTERNAL;
	}
	if (journal_apply() != 0) {
		/* Persisted journal is replayed at next boot. */
		g_tk.fault = true;
		return SW_INTERNAL;
	}
	return SW_OK;
}

