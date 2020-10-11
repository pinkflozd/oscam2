#define MODULE_LOG_PREFIX "stat"

#include "globals.h"

#ifdef WITH_LB
#include "cscrypt/md5.h"
#include "module-cacheex.h"
#include "module-cccam.h"
#include "oscam-array.h"
#include "oscam-cache.h"
#include "oscam-conf-chk.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-files.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "module-stat.h"

// do NOT set 0 or small value here! Could cause there reader get selected
#define UNDEF_AVG_TIME 99999

#define MAX_ECM_SEND_CACHE 16

#define LB_NONE 0
#define LB_FASTEST_READER_FIRST 1
#define LB_OLDEST_READER_FIRST 2
#define LB_LOWEST_USAGELEVEL 3

#define DEFAULT_LOCK_TIMEOUT 1000000
#define LINESIZE 1024

extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;
static int32_t stat_load_save;
static struct timeb last_housekeeping;

void init_stat(void)
{
	stat_load_save = -100;

	// checking config

	if (cfg.lb_nbest_readers < 2)
	{
		cfg.lb_nbest_readers = DEFAULT_NBEST;
	}

	if (cfg.lb_nfb_readers < 2)
	{
		cfg.lb_nfb_readers = DEFAULT_NFB;
	}

	if (cfg.lb_min_ecmcount < 2)
	{
		cfg.lb_min_ecmcount = DEFAULT_MIN_ECM_COUNT;
	}

	if (cfg.lb_max_ecmcount < 3)
	{
		cfg.lb_max_ecmcount = DEFAULT_MAX_ECM_COUNT;
	}

	if (cfg.lb_reopen_seconds < 10)
	{
		cfg.lb_reopen_seconds = DEFAULT_REOPEN_SECONDS;
	}

	if (cfg.lb_retrylimit < 0)
	{
		cfg.lb_retrylimit = DEFAULT_RETRYLIMIT;
	}

	if (cfg.lb_stat_cleanup <= 0)
	{
		cfg.lb_stat_cleanup = DEFAULT_LB_STAT_CLEANUP;
	}
}

static uint32_t get_prid(uint16_t caid, uint32_t prid)
{
	uint32_t i;
	CAIDTAB_DATA *d = NULL;
	uint16_t tcaid;

	for (i=0; i < (uint32_t)cfg.lb_noproviderforcaid.ctnum; i++)
	{
		d = &cfg.lb_noproviderforcaid.ctdata[i];

		if (d == NULL)
		{
			break;
		}
		else
		{
			tcaid = d->caid;
		}

		if (!tcaid)
		{
			break;
		}

		if ((tcaid == caid) || (tcaid < 0x0100 && (caid >> 8) == tcaid))
		{
			prid = 0;
			break;
		}

	}

	return prid;
}

static void get_stat_query(ECM_REQUEST *er, STAT_QUERY *q)
{
	if (er == NULL || q == NULL)
	{
		return;
	}

	memset(q, 0, sizeof(STAT_QUERY));

	q->caid = er->caid;
	q->prid = get_prid(er->caid, er->prid);
	q->srvid = er->srvid;
	q->chid = er->chid;
	q->ecmlen = er->ecmlen;
}

void load_stat_from_file(void)
{
	stat_load_save = 0;
	char buf[256];
	char *line = NULL;
	char *fname = NULL;
	FILE *file = NULL;

	struct s_reader *rdr = NULL;
	READER_STAT *s = NULL;

	uint32_t i = 1;
	uint32_t valid = 0;
	uint32_t count = 0;
	uint32_t type = 0;
	char *ptr = NULL;
	char *saveptr1 = NULL;
	char *split[12];

	struct timeb ts, te;


	if (!cfg.lb_savepath)
	{
		get_tmp_dir_filename(buf, sizeof(buf), "stat");
		fname = buf;
	}
	else
	{
		fname = cfg.lb_savepath;
	}

	if (fname == NULL)
	{
		cs_log("ERROR fname null!");
		return;
	}

	file = fopen(fname, "r");

	if (file == NULL)
	{
		cs_log_dbg(D_LB, "loadbalancer: could not open %s for reading (errno=%d %s)", fname, errno, strerror(errno));
		return;
	}

	if (!cs_malloc(&line, LINESIZE))
	{
		fclose(file);
		return;
	}

	cs_log_dbg(D_LB, "loadbalancer: load statistics from %s", fname);

	cs_ftime(&ts);

	while(fgets(line, LINESIZE, file))
	{
		if (!line[0] || line[0] == '#' || line[0] == ';')
		{
			continue;
		}

		if (!cs_malloc(&s, sizeof(READER_STAT)))
		{
			continue;
		}

		// get type by evaluating first line:
		if (type == 0)
		{
			if (strstr(line, " rc "))
			{
				type = 2;
			}
			else
			{
				type = 1;
			}
		}

		if (type == 1)	// New format - faster parsing
		{
			for (i = 0, ptr = strtok_r(line, ",", &saveptr1); ptr && i < 12 ; ptr = strtok_r(NULL, ",", &saveptr1), i++)
			{
				split[i] = ptr;
			}

			valid = (i == 11);

			if (valid)
			{
				cs_strncpy(buf, split[0], sizeof(buf));
				s->rc = atoi(split[1]);
				s->caid = a2i(split[2], 4);
				s->prid = a2i(split[3], 6);
				s->srvid = a2i(split[4], 4);
				s->chid = a2i(split[5], 4);
				s->time_avg = atoi(split[6]);
				s->ecm_count = atoi(split[7]);
				s->last_received.time = atol(split[8]);
				s->fail_factor = atoi(split[9]);
				s->ecmlen = a2i(split[10], 2);
			}
		}
		else	// Old format - keep for compatibility:
		{
			i = sscanf(line, "%255s rc %04d caid %04hX prid %06X srvid %04hX time avg %d ms ecms %d last %ld fail %d len %02hX\n",
					   buf, &s->rc, &s->caid, &s->prid, &s->srvid,
					   &s->time_avg, &s->ecm_count, &s->last_received.time, &s->fail_factor, &s->ecmlen);
			valid = i > 5;
		}

		if (valid && s->ecmlen > 0)
		{
			if (rdr == NULL || strcmp(buf, rdr->label) != 0)
			{
				LL_ITER itr = ll_iter_create(configured_readers);

				while((rdr = ll_iter_next(&itr)))
				{
					if (strcmp(rdr->label, buf) == 0)
					{
						break;
					}
				}
			}

			if (rdr != NULL && strcmp(buf, rdr->label) == 0)
			{
				if (rdr->lb_stat == NULL)
				{
					rdr->lb_stat = ll_create("lb_stat");
					cs_lock_create(__func__, &rdr->lb_stat_lock, rdr->label, DEFAULT_LOCK_TIMEOUT);
				}

				ll_append(rdr->lb_stat, s);
				count++;
			}
			else
			{
				cs_log("loadbalancer: statistics could not be loaded for %s", buf);
				NULLFREE(s);
			}
		}
		else
		{
			cs_log_dbg(D_LB, "loadbalancer: statistics ERROR: %s rc=%d i=%d", buf, s->rc, i);
			NULLFREE(s);
		}
	}

	fclose(file);
	NULLFREE(line);

	cs_ftime(&te);
#ifdef WITH_DEBUG
	int64_t load_time = comp_timeb(&te, &ts);

	cs_log_dbg(D_LB, "loadbalancer: statistics loaded %d records in %"PRId64" ms", count, load_time);
#endif
}

void lb_destroy_stats(struct s_reader *rdr)
{
	if (rdr == NULL)
	{
		return;
	}
	else
	{
		if (rdr->lb_stat == NULL)
		{
			return;
		}
	}

	cs_lock_destroy(__func__, &rdr->lb_stat_lock);
	ll_destroy_data(&rdr->lb_stat);
}

/**
 * get statistic values for reader ridx and caid/prid/srvid/ecmlen
 **/
static READER_STAT *get_stat_lock(struct s_reader *rdr, STAT_QUERY *q)
{
	READER_STAT *s = NULL;
	uint32_t i = 0;

	if (rdr == NULL || q == NULL)
	{
		cs_log_dbg(D_LB, "loadbalancer: Something is wrong with %s !", rdr->label);
		return NULL;
	}

	if (rdr->lb_stat == NULL)
	{
		cs_log_dbg(D_LB, "loadbalancer: %s lb_stat container created.", rdr->label);
		rdr->lb_stat = ll_create("lb_stat");
		cs_lock_create(__func__, &rdr->lb_stat_lock, rdr->label, DEFAULT_LOCK_TIMEOUT);
	}

	cs_readlock(__func__, &rdr->lb_stat_lock);

	LL_ITER it = ll_iter_create(rdr->lb_stat);

	while((s = ll_iter_next(&it)))
	{
		i++;

		if (s->caid == q->caid && s->prid == q->prid && s->srvid == q->srvid && s->chid == q->chid)
		{
			// Query without ecmlen from dvbapi
			if (!q->ecmlen)
			{
				break;
			}

			if (!s->ecmlen)
			{
				cs_readunlock(__func__, &rdr->lb_stat_lock);

				// Wait a bit if stat is busy
				while(rdr->lb_stat_busy);

				rdr->lb_stat_busy = 1;
				cs_writelock(__func__, &rdr->lb_stat_lock);

				s->ecmlen = q->ecmlen;

				cs_writeunlock(__func__, &rdr->lb_stat_lock);
				rdr->lb_stat_busy = 0;

				cs_readlock(__func__, &rdr->lb_stat_lock);

				break;
			}

			if (s->ecmlen == q->ecmlen)
			{
				break;
			}
		}
	}

	cs_readunlock(__func__, &rdr->lb_stat_lock);

	// Move stat to list start for faster access:
	if (i > 10 && s)
	{
		// Wait a bit if stat is busy
		while(rdr->lb_stat_busy);

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		ll_iter_move_first(&it);

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}

	return s;
}

/**
 * get statistic values for reader ridx and caid/prid/srvid/ecmlen
 **/
static READER_STAT *get_stat(struct s_reader *rdr, STAT_QUERY *q)
{
	if (rdr == NULL ||  q == NULL)
	{
		return NULL;
	}

	// Wait a bit if stat is busy
	while(rdr->lb_stat_busy);

	return get_stat_lock(rdr, q);
}

/**
 * Calculates average time
 */
static void calc_stat(READER_STAT *s, struct s_reader *rdr)
{
	uint32_t i;
	uint32_t c = 0;
	uint32_t t = 0;

	if (s == NULL)
	{
		return;
	}

	cs_readlock(__func__, &rdr->lb_stat_lock);

	for (i = 0; i < LB_MAX_STAT_TIME; i++)
	{
		if (s->time_stat[i] > 0)
		{
			t += (int32_t)s->time_stat[i];
			c++;
		}
	}

	cs_readunlock(__func__, &rdr->lb_stat_lock);

	// Wait a bit if stat is busy
	while(rdr->lb_stat_busy);

	rdr->lb_stat_busy = 1;
	cs_writelock(__func__, &rdr->lb_stat_lock);

	if (!c)
	{
		s->time_avg = UNDEF_AVG_TIME;
	}
	else
	{
		s->time_avg = t / c;
	}

	cs_writeunlock(__func__, &rdr->lb_stat_lock);
	rdr->lb_stat_busy = 0;
}

/**
 * Saves statistik to /tmp/.oscam/stat.n where n is reader-index
 */
static void save_stat_to_file_thread(void)
{
	stat_load_save = 0;
	char buf[256];
	char *fname = NULL;
	FILE *file = NULL;
	struct timeb ts, te;
	uint32_t cleanup_timeout;
	uint32_t count = 0;
	struct s_reader *rdr = NULL;

	memset(buf, 0, sizeof(buf));

	set_thread_name(__func__);

	if(!cfg.lb_savepath)
	{
		get_tmp_dir_filename(buf, sizeof(buf), "stat");
		fname = buf;
	}
	else
	{
		fname = cfg.lb_savepath;
	}

	if (fname == NULL)
	{
		cs_log("ERROR fname is null!");
		return;
	}

	file = fopen(fname, "w");

	if (file == NULL)
	{
		cs_log("can't write to file %s", fname);
		return;
	}

	cs_ftime(&ts);

	cleanup_timeout = (cfg.lb_stat_cleanup * 60 * 60 * 1000);

	LL_ITER itr = ll_iter_create(configured_readers);

	while((rdr = ll_iter_next(&itr)))
	{
		if (rdr->lb_stat)
		{
			// Wait a bit if stat is busy
			while(rdr->lb_stat_busy);

			rdr->lb_stat_busy = 1;
			cs_writelock(__func__, &rdr->lb_stat_lock);

			LL_ITER it = ll_iter_create(rdr->lb_stat);
			READER_STAT *s = NULL;

			while((s = ll_iter_next(&it)))
			{
				int64_t gone = comp_timeb(&ts, &s->last_received);
				if (gone > cleanup_timeout || !s->ecmlen) // cleanup old stats
				{
					ll_iter_remove_data(&it);
					continue;
				}

				//Old version, too slow to parse:
				//fprintf(file, "%s rc %d caid %04hX prid %06X srvid %04hX time avg %d ms ecms %d last %ld fail %d len %02hX\n",
				//  rdr->label, s->rc, s->caid, s->prid,
				//  s->srvid, s->time_avg, s->ecm_count, s->last_received, s->fail_factor, s->ecmlen);

				//New version:
				fprintf(file, "%s,%d,%04hX,%06X,%04hX,%04hX,%d,%d,%ld,%d,%02hX\n",
						rdr->label, s->rc, s->caid, s->prid,
						s->srvid, (uint16_t)s->chid, s->time_avg, s->ecm_count, s->last_received.time, s->fail_factor, s->ecmlen);

				count++;
				//if(count % 500 == 0) { // Saving stats is using too much cpu and causes high file load. so we need a break
				//	cs_readunlock(__func__, &rdr->lb_stat_lock);
				//	cs_sleepms(100);
				//	cs_readlock(__func__, &rdr->lb_stat_lock);
				//}
			}

			cs_writeunlock(__func__, &rdr->lb_stat_lock);
			rdr->lb_stat_busy = 0;
		}
	}

	if (file)
	{
		fclose(file);
	}

	cs_ftime(&te);
	int64_t load_time = comp_timeb(&te, &ts);

	cs_log("loadbalancer: statistic saved %d records to %s in %"PRId64" ms", count, fname, load_time);
}

void save_stat_to_file(int32_t thread)
{
	stat_load_save = 0;

	if (thread)
	{
		start_thread("save lb stats", (void *)&save_stat_to_file_thread, NULL, NULL, 1, 1);
	}
	else
	{
		save_stat_to_file_thread();
	}
}

/**
 * This function increases the fail_factor
 **/
static void inc_fail(READER_STAT *s)
{
	if (s == NULL)
	{
		return;
	}
	else
	{
		if (s->fail_factor <= 0)
		{
			s->fail_factor = 1;
		}
		else
		{
			if (s->fail_factor > 0)
			{
				// inc by one at the time
				s->fail_factor++;
			}
		}
	}
}

static READER_STAT *get_add_stat(struct s_reader *rdr, STAT_QUERY *q)
{
	READER_STAT *s = NULL;

	if (rdr == NULL || q == NULL)
	{
		return NULL;
	}

	// wait a bit if stat is busy
	while(rdr->lb_stat_busy)

	if (rdr->lb_stat == NULL)
	{
		cs_log_dbg(D_LB, "loadbalancer: %s lb_stat container created.", rdr->label);
		rdr->lb_stat = ll_create("lb_stat");
		cs_lock_create(__func__, &rdr->lb_stat_lock, rdr->label, DEFAULT_LOCK_TIMEOUT);
	}

	s = get_stat_lock(rdr, q);

	if (s == NULL)
	{
		if (cs_malloc(&s, sizeof(READER_STAT)))
		{
			rdr->lb_stat_busy = 1;
			cs_writelock(__func__, &rdr->lb_stat_lock);

			s->caid = q->caid;
			s->prid = q->prid;
			s->srvid = q->srvid;
			s->chid = q->chid;
			s->ecmlen = q->ecmlen;
			s->time_avg = UNDEF_AVG_TIME; // dummy placeholder
			s->rc = E_FOUND; // set to found--> do not change!
			cs_ftime(&s->last_received);
			s->fail_factor = 0;
			s->ecm_count = 0;
			ll_prepend(rdr->lb_stat, s);

			cs_writeunlock(__func__, &rdr->lb_stat_lock);
			rdr->lb_stat_busy = 0;
		}
	}

	return s;
}

static void housekeeping_stat(int32_t force);

static int32_t get_reopen_seconds(READER_STAT *s, struct s_reader *rdr)
{
	if (s == NULL)
	{
		return cfg.lb_reopen_seconds;
	}

	int32_t max = (INT_MAX / cfg.lb_reopen_seconds);

	if (max > 9999)
	{
		max = 9999;
	}

	if (s->fail_factor > max)
	{
		// Wait a bit if stat is busy
		while(rdr->lb_stat_busy);

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		s->fail_factor = max;

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}

	if (!s->fail_factor)
	{
		return cfg.lb_reopen_seconds;
	}

	//return s->fail_factor * cfg.lb_reopen_seconds;
	return cfg.lb_reopen_seconds;
}

/**
 * Adds caid/prid/srvid/ecmlen to stat-list for reader ridx with time/rc
 */
static void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int32_t ecm_time, int32_t rc, uint8_t rcEx)
{
	//inc ecm_count if found, drop to 0 if not found:
	// rc codes:
	// 0 = found       +
	// 1 = cache1      #
	// 2 = cache2      #
	// 3 = cacheex     #
	// 4 = not found   -
	// 5 = timeout     -
	// 6 = sleeping    #
	// 7 = fake        -
	// 8 = invalid     -
	// 9 = corrupt     #
	// 10= no card     #
	// 11= expdate     #
	// 12= disabled    #
	// 13= stopped     #
	// 100= unhandled  #
	//        + = adds statistic values
	//        # = ignored because of duplicate values, temporary failures or softblocks
	//        - = causes loadbalancer to block this reader for this caid/prov/sid

	if (rdr == NULL || er == NULL || !cfg.lb_mode)
	{
		return;
	}

	if (!er->ecmlen || !er->client)
	{
		return;
	}

	// Wait a bit if stat is busy
	while(rdr->lb_stat_busy);

	struct s_client *cl = rdr->client;
	if (!check_client(cl))
	{
		return;
	}

	// IGNORE stats for fallback reader with lb_force_fallback parameter
	if (chk_is_fixed_fallback(rdr, er) && rdr->lb_force_fallback)
	{
		return;
	}

	// IGNORE fails for ratelimit check
	if (rc == E_NOTFOUND && rcEx == E2_RATELIMIT)
	{
#ifdef WITH_DEBUG
		if ((D_LB & cs_dblevel))
		{
			char buf[ECM_FMT_LEN];
			format_ecm(er, buf, ECM_FMT_LEN);
			cs_log_dbg(D_LB, "loadbalancer: NOT adding stat (blocking) for reader %s because fails ratelimit checks!", rdr->label);
		}
#endif
		return;
	}

	// IGNORE fails when reader has positive services defined in new lb_whitelist_services parameter! See ticket #3310,#3311
	if (rc >= E_NOTFOUND && has_lb_srvid(cl, er))
	{
#ifdef WITH_DEBUG
		if ((D_LB & cs_dblevel))
		{
			char buf[ECM_FMT_LEN];
			format_ecm(er, buf, ECM_FMT_LEN);
			cs_log_dbg(D_LB, "loadbalancer: NOT adding stat (blocking) for reader %s because has positive srvid: rc %d %s time %d ms",
						rdr->label, rc, buf, ecm_time);
		}
#endif
		return;
	}


	// IGNORE fails for sleep CMD08
	if (rc == E_NOTFOUND && rdr->client->stopped==2)
	{
#ifdef WITH_DEBUG
		if ((D_LB & cs_dblevel))
		{
			char buf[ECM_FMT_LEN];
			format_ecm(er, buf, ECM_FMT_LEN);
			cs_log_dbg(D_LB, "loadbalancer: NOT adding stat (no block) for reader %s because CMD08 sleep command!", rdr->label);
		}
#endif
		return;
	}

	// IGNORE timeouts on local readers (they could be busy handling an emm or entitlement refresh)
	if (rc == E_TIMEOUT && !is_network_reader(rdr))
	{
#ifdef WITH_DEBUG
		if ((D_LB & cs_dblevel))
		{
			cs_log_dbg(D_LB, "loadbalancer: NOT adding stat (no block) for reader %s because timeout on local reader", rdr->label);
		}
#endif
		return;
	}

	// IGNORE unhandled ecmresponses
	if (rc == E_UNHANDLED)
	{
#ifdef WITH_DEBUG
		if ((D_LB & cs_dblevel))
		{
			cs_log_dbg(D_LB, "loadbalancer: NOT adding stat (no block) for reader %s because unhandled reponse", rdr->label);
		}
#endif
		return;
	}

	// ignore too old ecms
	if ((uint32_t)ecm_time >= 3 * cfg.ctimeout)
	{
		return;
	}

	if ((uint32_t)ecm_time >= cfg.ctimeout)
	{
		rc = E_TIMEOUT;
	}

	STAT_QUERY q;
	get_stat_query(er, &q);
	READER_STAT *s = NULL;

	s = get_add_stat(rdr, &q);

	if (s == NULL)
	{
		return;
	}

	struct timeb now;
	cs_ftime(&now);
	cs_ftime(&s->last_received);

	if (rc == E_FOUND)
	{
		// Wait a bit if stat is busy
		while(rdr->lb_stat_busy);

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		s->rc = E_FOUND;
		s->ecm_count++;

		if (s->ecm_count < cfg.lb_min_ecmcount || s->ecm_count > cfg.lb_max_ecmcount)
		{
			s->fail_factor = 0;
		}
		if (s->fail_factor > 0 && s->fail_factor > s->ecm_count)
		{
			s->fail_factor = s->ecm_count;
		}
		// FASTEST READER:
		s->time_idx++;
		if(s->time_idx >= LB_MAX_STAT_TIME)
			{ s->time_idx = 0; }
		s->time_stat[s->time_idx] = ecm_time;

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;

		calc_stat(s, rdr);

		// OLDEST READER now set by get best reader!

		// USAGELEVEL:
		/* Assign a value to rdr->lb_usagelevel_ecmcount,
		because no determined value was assigned before. */
		if(rdr->lb_usagelevel_ecmcount < 0)
			{ rdr->lb_usagelevel_ecmcount = 0; }

		rdr->lb_usagelevel_ecmcount++; /* ecm is found so counter should increase */
		if((rdr->lb_usagelevel_ecmcount % cfg.lb_min_ecmcount) == 0)  //update every MIN_ECM_COUNT usagelevel:
		{
			int64_t t = comp_timeb(&now, &rdr->lb_usagelevel_time) / 1000;
			rdr->lb_usagelevel = cfg.lb_min_ecmcount * 1000 / (t < 1 ? 1 : t);
			/* Reset of usagelevel time and counter */
			rdr->lb_usagelevel_time = now;
			rdr->lb_usagelevel_ecmcount = 0;
		}
	}
	else if (rc == E_NOTFOUND || rc == E_TIMEOUT || rc == E_FAKE)
	{
		// Wait a bit if stat is busy
		while(rdr->lb_stat_busy);

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		inc_fail(s);
		s->rc = rc;
		s->ecm_count++;

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}
	else if (rc == E_INVALID)
	{
		// Wait a bit if stat is busy
		while(rdr->lb_stat_busy);

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		inc_fail(s);
		s->rc = rc;
		s->ecm_count++;

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}
	else
	{
#ifdef WITH_DEBUG
		if (rc >= E_FOUND && (D_LB & cs_dblevel))
		{
			char buf[ECM_FMT_LEN];
			format_ecm(er, buf, ECM_FMT_LEN);
			cs_log_dbg(D_LB, "loadbalancer: not handled stat for reader %s: rc %d %s time %d ms",
						rdr->label, rc, buf, ecm_time);
		}
#endif
		return;
	}

	housekeeping_stat(0);

#ifdef WITH_DEBUG
	if (D_LB & cs_dblevel)
	{
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_log_dbg(D_LB, "loadbalancer: adding stat for reader %s: rc %d %s time %d ms fail %d",
					rdr->label, rc, buf, ecm_time, s->fail_factor);
	}
#endif

	if (cfg.lb_save)
	{
		stat_load_save++;

		if (stat_load_save > cfg.lb_save)
		{
			save_stat_to_file(1);
		}
	}
}

int32_t clean_stat_by_rc(struct s_reader *rdr, int8_t rc, int8_t inverse)
{
	int32_t count = 0;
	if(rdr && rdr->lb_stat)
	{
		// Wait a bit if stat is busy
		while(rdr->lb_stat_busy);

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		READER_STAT *s;
		LL_ITER itr = ll_iter_create(rdr->lb_stat);
		while((s = ll_iter_next(&itr)))
		{
			if((!inverse && s->rc == rc) || (inverse && s->rc != rc))
			{
				ll_iter_remove_data(&itr);
				count++;
			}
		}

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}

	return count;
}

int32_t clean_all_stats_by_rc(int8_t rc, int8_t inverse)
{
	int32_t count = 0;
	LL_ITER itr = ll_iter_create(configured_readers);
	struct s_reader *rdr;

	while((rdr = ll_iter_next(&itr)))
	{
		count += clean_stat_by_rc(rdr, rc, inverse);
	}

	save_stat_to_file(0);

	return count;
}

int32_t clean_stat_by_id(struct s_reader *rdr, uint16_t caid, uint32_t prid, uint16_t srvid, uint16_t chid, uint16_t ecmlen)
{
	int32_t count = 0;

	if (rdr == NULL)
	{
		return count;
	}

	if (rdr && rdr->lb_stat)
	{
		// Wait a bit if stat is busy
		while(rdr->lb_stat_busy);

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		READER_STAT *s;
		LL_ITER itr = ll_iter_create(rdr->lb_stat);
		while((s = ll_iter_next(&itr)))
		{
			if (s->caid == caid &&
					s->prid == prid &&
					s->srvid == srvid &&
					s->chid == chid &&
					s->ecmlen == ecmlen)
			{
				ll_iter_remove_data(&itr);
				count++;
				break; // because the entry should unique we can left here
			}
		}

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}
	return count;
}

/*
static int32_t has_ident(FTAB *ftab, ECM_REQUEST *er)
{
	uint32_t j, k;

	if (ftab == NULL || er == NULL)
	{
		return 0;
	}

	if (!ftab->filts)
	{
		return 0;
	}

	for (j = 0; j < ftab->nfilts; j++)
	{
		if (ftab->filts[j].caid)
		{
			// caid matches!
			if (ftab->filts[j].caid==er->caid)
			{
				int32_t nprids = ftab->filts[j].nprids;

				// No Provider ->Ok
				if (!nprids)
				{
					return 1;
				}

				for (k = 0; k < nprids; k++)
				{
					uint32_t prid = ftab->filts[j].prids[k];

					// Provider matches
					if (prid == er->prid)
					{
						return 1;
					}
				}
			}
		}
	}

	return 0; // No match!
}*/

static int32_t get_retrylimit(ECM_REQUEST *er)
{
	return caidvaluetab_get_value(&cfg.lb_retrylimittab, er->caid, cfg.lb_retrylimit);
}

static int32_t get_nfb_readers(ECM_REQUEST *er)
{
	// default value
	int32_t nfb_readers = 1;

	if (er == NULL)
	{
		return nfb_readers;
	}

	nfb_readers = er->client->account->lb_nfb_readers == -1 ? cfg.lb_nfb_readers : er->client->account->lb_nfb_readers;

	if (nfb_readers <= 0)
	{
		nfb_readers = 1;
	}

	return nfb_readers;
}

static int32_t get_nbest_readers(ECM_REQUEST *er)
{
	// default value
	int32_t nbest_readers = 1;

	if (er == NULL)
	{
		return nbest_readers;
	}

	nbest_readers = er->client->account->lb_nbest_readers == -1 ? cfg.lb_nbest_readers : er->client->account->lb_nbest_readers;
	CAIDVALUETAB *nbest_readers_tab = er->client->account->lb_nbest_readers_tab.cvnum == 0 ? &cfg.lb_nbest_readers_tab : &er->client->account->lb_nbest_readers_tab;

	if (nbest_readers <= 0)
	{
		nbest_readers = 1;
	}

	return caidvaluetab_get_value(nbest_readers_tab, er->caid, nbest_readers);
}

static void convert_to_beta_int(ECM_REQUEST *er, uint16_t caid_to)
{
	uint8_t md5tmp[MD5_DIGEST_LENGTH];

	memset(md5tmp, 0, sizeof(md5tmp));

	if (er == NULL)
	{
		return;
	}

	convert_to_beta(er->client, er, caid_to);

	// update ecmd5 for store ECM in cache
	memcpy(er->ecmd5, MD5(er->ecm + 13, er->ecmlen - 13, md5tmp), CS_ECMSTORESIZE);

	cacheex_update_hash(er);

	// marked as auto-betatunnel converted. Also for fixing recursive lock in get_cw
	er->btun = 2;
}

static void convert_to_nagra_int(ECM_REQUEST *er, uint16_t caid_to)
{
	uint8_t md5tmp[MD5_DIGEST_LENGTH];

	memset(md5tmp, 0, sizeof(md5tmp));

	if (er == NULL)
	{
		return;
	}

	convert_to_nagra(er->client, er, caid_to);

	// update ecmd5 for store ECM in cache
	memcpy(er->ecmd5, MD5(er->ecm + 3, er->ecmlen - 3, md5tmp), CS_ECMSTORESIZE);

	cacheex_update_hash(er);

	// marked as auto-betatunnel converted. Also for fixing recursive lock in get_cw
	er->btun = 2;
}

static int32_t lb_valid_btun(ECM_REQUEST *er, uint16_t caidto)
{
	STAT_QUERY q;
	READER_STAT *s = NULL;
	struct s_reader *rdr = NULL;

	if (er == NULL)
	{
		return 0;
	}

	get_stat_query(er, &q);
	q.caid = caidto;

	cs_readlock(__func__, &readerlist_lock);

	for (rdr = first_active_reader; rdr ; rdr = rdr->next)
	{
		if (rdr->lb_stat && rdr->client)
		{
			s = get_stat(rdr, &q);

			if (s == NULL)
			{
				return 0;
			}
			else
			{
				if (s->rc == E_FOUND)
				{
					cs_readunlock(__func__, &readerlist_lock);
					return 1;
				}
			}
		}
	}

	cs_readunlock(__func__, &readerlist_lock);

	return 0;
}

static uint16_t __lb_get_betatunnel_caid_to(uint16_t caid)
{
	int32_t lbbm = cfg.lb_auto_betatunnel_mode;
	if(lbbm <= 3)
	{
		if(caid == 0x1801) { return 0x1722; }
		if(caid == 0x1833) { return 0x1702; }
		if(caid == 0x1834) { return 0x1722; }
		if(caid == 0x1835) { return 0x1722; }
	}
	if(lbbm >= 1)
	{
		if(caid == 0x1702) { return 0x1833; }
	}
	if(lbbm == 1 || lbbm == 4)
	{
		if(caid == 0x1722) { return 0x1801; }
	}
	else if(lbbm == 2 || lbbm == 5)
	{
		if(caid == 0x1722) { return 0x1834; }
	}
	else if(lbbm == 3 || lbbm == 6)
	{
		if(caid == 0x1722) { return 0x1835; }
	}
	return 0;
}

uint16_t lb_get_betatunnel_caid_to(ECM_REQUEST *er)
{
	uint16_t caidto = 0;

	if (er == NULL)
	{
		return 0;
	}

	if (!cfg.lb_auto_betatunnel)
	{
		return 0;
	}

	caidto = __lb_get_betatunnel_caid_to(er->caid);

	if (lb_valid_btun(er, caidto))
	{
		return caidto;
	}

	return 0;
}

void check_lb_auto_betatunnel_mode(ECM_REQUEST *er)
{
	uint32_t lbbm = 0;

	if (er == NULL)
	{
		return;
	}

	lbbm = cfg.lb_auto_betatunnel_mode;

	if(lbbm == 1 || lbbm == 4)
	{
		er->caid = 0x1801;
	}
	else if (lbbm == 2 || lbbm == 5)
	{
		er->caid = 0x1834;
	}
	else if (lbbm == 3 || lbbm == 6)
	{
		er->caid = 0x1835;
	}
	// no other way to autodetect 1801, 1834 or 1835
}

uint16_t get_rdr_caid(struct s_reader *rdr)
{
	if (rdr == NULL)
	{
		return 0;
	}

	if (is_network_reader(rdr) || rdr->typ == R_EMU)
	{
		return 0; // reader caid is not real caid
	}
	else
	{
		return rdr->caid;
	}
}

static void reset_ecmcount_reader(READER_STAT *s, struct s_reader *rdr)
{
	if (s == NULL || rdr == NULL)
	{
		return;
	}

	if (rdr->lb_stat && rdr->client)
	{
		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		s->ecm_count = 0;

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}
}

static void reset_avgtime_reader(READER_STAT *s, struct s_reader *rdr)
{
	if (s == NULL || rdr == NULL)
	{
		return;
	}

	if (rdr->lb_stat && rdr->client)
	{
		uint32_t i;

		rdr->lb_stat_busy = 1;
		cs_writelock(__func__, &rdr->lb_stat_lock);

		for (i=0; i < LB_MAX_STAT_TIME; i++)
		{
			if (s->time_stat[i] > 0)
			{
				s->time_stat[i] = 0;
			}
		}

		s->time_avg = UNDEF_AVG_TIME;

		cs_writeunlock(__func__, &rdr->lb_stat_lock);
		rdr->lb_stat_busy = 0;
	}
}

/* force_reopen=1 -> force opening of block readers
 * force_reopen=0 -> no force opening of block readers, use reopen_seconds
 */
static void try_open_blocked_readers(ECM_REQUEST *er, STAT_QUERY *q, int32_t max_reopen, int32_t force_reopen)
{
	struct s_ecm_answer *ea = NULL;
	READER_STAT *s = NULL;
	struct s_reader *rdr = NULL;

	if (er == NULL || q == NULL)
	{
		return;
	}

	for (ea = er->matching_rdr; ea; ea = ea->next)
	{
		if ((ea->status & READER_FALLBACK) || (ea->status & READER_ACTIVE))
		{
			continue;
		}

		rdr = ea->reader;

		if (rdr == NULL)
		{
			continue;
		}

		s = get_stat(rdr, q);

		if (s == NULL)
		{
			continue;
		}

		if (!cfg.lb_reopen_invalid && s->rc == E_INVALID)
		{
			cs_log_dbg(D_LB, "loadbalancer: reader %s blocked because INVALID sent! It will be blocked until stats cleaned!", rdr->label);
			continue;
		}

		// if force_reopen flag is set and lb_force_reopen_always=1 we must activate reader
		if (force_reopen && cfg.lb_force_reopen_always)
		{
			cs_log_dbg(D_LB, "loadbalancer: force_reopen is set so opening reader %s and reseting fail_factor! --> ACTIVE", rdr->label);
			ea->status |= READER_ACTIVE;
			s->fail_factor = 0;
			continue;
		}

		// Activate reader reached reopen seconds.
		struct timeb now;
		cs_ftime(&now);
		int64_t gone = comp_timeb(&now, &s->last_received);
		int32_t reopenseconds = get_reopen_seconds(s, rdr);

		if (gone > (int64_t)(reopenseconds * 1000))
		{
			if (max_reopen > 0)
			{
				cs_log_dbg(D_LB, "loadbalancer: reader %s reaches %d seconds for reopening (fail_factor %d) --> ACTIVE", rdr->label, reopenseconds, s->fail_factor);
				ea->status |= READER_ACTIVE;
				max_reopen--;
			}
			else
			{
				cs_log_dbg(D_LB, "loadbalancer: reader %s reaches %d seconds for reopening (fail_factor %d), but max_reopen reached!", rdr->label, reopenseconds, s->fail_factor);
			}

			continue;
		}

		// for debug output
		if (s->rc != E_FOUND)
		{
			cs_log_dbg(D_LB, "loadbalancer: reader %s blocked for %d seconds (fail_factor %d), retrying in %d seconds", rdr->label, reopenseconds, s->fail_factor, (uint) (reopenseconds - (gone/1000)));
			continue;
		}

		// for debug output
		if (s->rc == E_FOUND)
		{
			cs_log_dbg(D_LB, "loadbalancer: reader %s \"e_found\" but not selected for lbvalue check", rdr->label);
		}
	}
}

static float tol_calc_f = 0.0;
static uint32_t tol_calc = 0;

/*
 * Gets best reader for caid/prid/srvid/ecmlen.
 * Best reader is evaluated by lbmode selection, ecm_count must be >= cfg.lb_min_ecmcount
 * Also the reader is asked if he is "available"
 */
void stat_get_best_reader(ECM_REQUEST *er)
{
	struct s_reader *rdr = NULL;
	struct s_ecm_answer *ea = NULL;

	if (er == NULL)
	{
		return;
	}

	if (!cfg.lb_mode || cfg.lb_mode > 3)
	{
		return;
	}

	if (!er->reader_avail)
	{
		return;
	}

	// preferred card forwarding (CCcam client):
	if (cccam_forward_origin_card(er))
	{
		return;
	}

	STAT_QUERY q;
	get_stat_query(er, &q);

	// auto-betatunnel: The trick is: "let the loadbalancer decide"!
	if(cfg.lb_auto_betatunnel && caid_is_nagra(er->caid) && er->ecmlen) // nagra
	{
		uint16_t caid_to = __lb_get_betatunnel_caid_to(er->caid);
		if(caid_to)
		{
			int8_t needs_stats_nagra = 1, needs_stats_beta = 1;

			// Clone query parameters for beta:
			STAT_QUERY qbeta = q;
			qbeta.caid = caid_to;
			qbeta.prid = 0;
			qbeta.ecmlen = er->ecm[2] + 3 + 10;

			int32_t time_nagra = 0;
			int32_t time_beta = 0;
			int32_t weight;
			int32_t ntime;

			READER_STAT *stat_nagra = NULL;
			READER_STAT *stat_beta = NULL;

			// What is faster? nagra or beta?
			int8_t isn;
			int8_t isb;
			int8_t overall_valid = 0;
			int8_t overall_nvalid = 0;
			for(ea = er->matching_rdr; ea; ea = ea->next)
			{
				isn = 0;
				isb = 0;
				rdr = ea->reader;
				weight = rdr->lb_weight;
				if(weight <= 0) { weight = 1; }

				// Check if betatunnel is allowed on this reader:
				int8_t valid = chk_ctab(caid_to, &rdr->ctab) //Check caid
								&& chk_rfilter2(caid_to, 0, rdr) //Ident
								&& chk_srvid_by_caid_prov_rdr(rdr, caid_to, 0) //Services
								&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr, caid_to)); //rdr-caid
				if(valid)
				{
					stat_beta = get_stat(rdr, &qbeta);
					overall_valid = 1;
				}
				//else
				//stat_beta = NULL;

				// Check if nagra is allowed on this reader:
				int8_t nvalid = chk_ctab(er->caid, &rdr->ctab)//Check caid
								&& chk_rfilter2(er->caid, 0, rdr) //Ident
								&& chk_srvid_by_caid_prov_rdr(rdr, er->caid, 0) //Services
								&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr, er->caid)); //rdr-caid
				if(nvalid)
				{
					stat_nagra = get_stat(rdr, &q);
					overall_nvalid = 1;
				}

				// calculate nagra data:
				if(stat_nagra && stat_nagra->rc == E_FOUND)
				{
					ntime = stat_nagra->time_avg * 100 / weight;
					if(!time_nagra || ntime < time_nagra)
						{ time_nagra = ntime; }
				}

				// calculate beta data:
				if(stat_beta && stat_beta->rc == E_FOUND)
				{
					ntime = stat_beta->time_avg * 100 / weight;
					if(!time_beta || ntime < time_beta)
						{ time_beta = ntime; }
				}

				// Uncomplete reader evaluation, we need more stats!
				if(stat_nagra)
				{
					needs_stats_nagra = 0;
					isn = 1;
				}
				if(stat_beta)
				{
					needs_stats_beta = 0;
					isb = 1;
				}
				cs_log_dbg(D_LB, "loadbalancer-betatunnel valid %d, stat_nagra %d, stat_beta %d, (%04X,%04X)", valid, isn, isb , get_rdr_caid(rdr), caid_to);
			}

			if(!overall_valid) // we have no valid betatunnel reader also we don't needs stats (converted)
				{ needs_stats_beta = 0; }

			if(!overall_nvalid) // we have no valid reader also we don't needs stats (unconverted)
				{ needs_stats_nagra = 0; }

			if(cfg.lb_auto_betatunnel_prefer_beta && time_beta)
			{
				time_beta = time_beta * cfg.lb_auto_betatunnel_prefer_beta / 100;
				if(time_beta <= 0)
					{ time_beta = 1; }
			}

			if(needs_stats_nagra || needs_stats_beta)
			{
				cs_log_dbg(D_LB, "loadbalancer-betatunnel %04X:%04X (%d/%d) needs more statistics...", er->caid, caid_to,
							needs_stats_nagra, needs_stats_beta);
				if(needs_stats_beta) // try beta first
				{

					convert_to_beta_int(er, caid_to);
					get_stat_query(er, &q);
				}
			}
			else if(time_beta && (!time_nagra || time_beta <= time_nagra))
			{
				cs_log_dbg(D_LB, "loadbalancer-betatunnel %04X:%04X selected beta: n%d ms > b%d ms", er->caid, caid_to, time_nagra, time_beta);
				convert_to_beta_int(er, caid_to);
				get_stat_query(er, &q);
			}
			else
			{
				cs_log_dbg(D_LB, "loadbalancer-betatunnel %04X:%04X selected nagra: n%d ms < b%d ms", er->caid, caid_to, time_nagra, time_beta);
			}
			// else nagra is faster or no beta, so continue unmodified
		}
	}
	else
	{
		if(cfg.lb_auto_betatunnel && (er->caid == 0x1702 || er->caid == 0x1722) && er->ocaid == 0x0000 && er->ecmlen) // beta
		{
			uint16_t caid_to = __lb_get_betatunnel_caid_to(er->caid);
			if(caid_to)
			{
				int8_t needs_stats_nagra = 1, needs_stats_beta = 1;

				// Clone query parameters for beta:
				STAT_QUERY qnagra = q;
				qnagra.caid = caid_to;
				qnagra.prid = 0;
				qnagra.ecmlen = er->ecm[2] - 7;

				int32_t time_nagra = 0;
				int32_t time_beta = 0;
				int32_t weight;
				int32_t avg_time;

				READER_STAT *stat_nagra = NULL;
				READER_STAT *stat_beta = NULL;
				//What is faster? nagra or beta?
				int8_t isb;
				int8_t isn;
				int8_t overall_valid = 0;
				int8_t overall_bvalid = 0;
				for(ea = er->matching_rdr; ea; ea = ea->next)
				{
					isb = 0;
					isn = 0;
					rdr = ea->reader;
					weight = rdr->lb_weight;
					if(weight <= 0) { weight = 1; }

					//Check if reverse betatunnel is allowed on this reader:
					int8_t valid = chk_ctab(caid_to, &rdr->ctab)//, rdr->typ) //Check caid
									&& chk_rfilter2(caid_to, 0, rdr) //Ident
									&& chk_srvid_by_caid_prov_rdr(rdr, caid_to, 0) //Services
									&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr, caid_to)); //rdr-caid
					if(valid)
					{
						stat_nagra = get_stat(rdr, &qnagra);
						overall_valid = 1;
					}
					//else
					//stat_nagra = NULL;

					// Check if beta is allowed on this reader:
					int8_t bvalid = chk_ctab(er->caid, &rdr->ctab)//, rdr->typ) //Check caid
									&& chk_rfilter2(er->caid, 0, rdr) //Ident
									&& chk_srvid_by_caid_prov_rdr(rdr, er->caid, 0) //Services
									&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr, er->caid)); //rdr-caid
					if(bvalid)
					{
						stat_beta = get_stat(rdr, &q);
						overall_bvalid = 1;
					}

					// calculate nagra data:
					if(stat_nagra && stat_nagra->rc == E_FOUND)
					{
						avg_time = stat_nagra->time_avg * 100 / weight;
						if(!time_nagra || avg_time < time_nagra)
							{ time_nagra = avg_time; }
					}

					// calculate beta data:
					if(stat_beta && stat_beta->rc == E_FOUND)
					{
						avg_time = stat_beta->time_avg * 100 / weight;
						if(!time_beta || avg_time < time_beta)
							{ time_beta = avg_time; }
					}

					// Uncomplete reader evaluation, we need more stats!
					if(stat_beta)
					{
						needs_stats_beta = 0;
						isb = 1;
					}
					if(stat_nagra)
					{
						needs_stats_nagra = 0;
						isn = 1;
					}
					cs_log_dbg(D_LB, "loadbalancer-betatunnel valid %d, stat_beta %d, stat_nagra %d, (%04X,%04X)", valid, isb, isn , get_rdr_caid(rdr), caid_to);
				}

				if(!overall_valid) // we have no valid reverse betatunnel reader also we don't needs stats (converted)
					{ needs_stats_nagra = 0; }

				if(!overall_bvalid) // we have no valid reader also we don't needs stats (unconverted)
					{ needs_stats_beta = 0; }

				if(cfg.lb_auto_betatunnel_prefer_beta && time_beta)
				{
					time_beta = time_beta * cfg.lb_auto_betatunnel_prefer_beta / 100;
					if(time_beta < 0)
						{ time_beta = 0; }
				}

				// if we needs stats, we send 2 ecm requests: 18xx and 17xx:
				if(needs_stats_nagra || needs_stats_beta)
				{
					cs_log_dbg(D_LB, "loadbalancer-betatunnel %04X:%04X (%d/%d) needs more statistics...", er->caid, caid_to,
								needs_stats_beta, needs_stats_nagra);
					if(needs_stats_nagra) // try nagra frist
					{

						convert_to_nagra_int(er, caid_to);
						get_stat_query(er, &q);

					}
				}
				else if(time_nagra && (!time_beta || time_nagra <= time_beta))
				{
					cs_log_dbg(D_LB, "loadbalancer-betatunnel %04X:%04X selected nagra: b%d ms > n%d ms", er->caid, caid_to, time_beta, time_nagra);
					convert_to_nagra_int(er, caid_to);
					get_stat_query(er, &q);
				}
				else
				{
					cs_log_dbg(D_LB, "loadbalancer-betatunnel %04X:%04X selected beta: b%d ms < n%d ms", er->caid, caid_to, time_beta, time_nagra);
				}

			}
		}
	}

	if(cfg.lb_auto_betatunnel && chk_is_betatunnel_caid(er->caid))
	{
		// check again is caid valied to reader
		// with both caid on local readers or with proxy
		// (both caid will setup to reader for make tunnel caid in share (ccc) visible)
		// make sure dosn't send a beta ecm to nagra reader (or reverse)
		struct s_ecm_answer *prv = NULL;
		for(ea = er->matching_rdr; ea; ea = ea->next)
		{
			rdr = ea->reader;
			if(is_network_reader(rdr) || rdr->typ == R_EMU) // reader caid is not real caid
			{
				prv = ea;
				continue; // proxy can convert or reject
			}
			cs_log_dbg(D_LB, "check again caid %04X on reader %s", er->caid, rdr->label);

			if(!get_rdr_caid(ea->reader) || chk_caid_rdr(ea->reader, er->caid))
			{
				prv = ea;
			}
			else
			{
				if(!chk_is_fixed_fallback(rdr, er)) { er->reader_avail--; }
				cs_log_dbg(D_LB, "caid %04X not found in caidlist, reader %s removed from request reader list", er->caid, rdr->label);
				if(prv)
				{
					prv->next = ea->next;
				}
				else
					{ er->matching_rdr = ea->next; }
			}
		}

		if(!er->reader_avail)
			{ return; }
	}

	struct timeb check_time;
	int64_t current = -1;
	READER_STAT *s = NULL;
	int32_t retrylimit = get_retrylimit(er);

	int32_t force_reopen = 0;

	uint8_t nbest_readers = (uint8_t)get_nbest_readers(er); // Number of NON fallback readers ecm requests go (minimum 1)
	uint8_t nfb_readers = (uint8_t)get_nfb_readers(er); // Number of fallback readers ecm requests go (minimum 1)
	uint8_t lbmaxreaders = (uint8_t)cfg.lb_max_readers; // lb_max_readers is limit lb uses while learning
	uint8_t readers_active = 0;
	uint8_t fb_readers_active = 0;
	uint8_t readers_under_retrylimit = 0;
	uint8_t readers_over_retrylimit = 0;
	uint32_t readers_total = 0; // total matching readers sum
	int64_t prev_current = -1;
	int64_t prev_currentus = -1;
	uint8_t fbm = 0;
	uint8_t bsm = 0;

	cs_log_dbg(D_LB, "loadbalancer: --------------------------------------------");
	cs_log_dbg(D_LB, "loadbalancer: Current configuration: lb_mode %d, lb_nbest_readers %d, lb_nfb_readers %d, lb_max_readers %d, matching readers %d, lb_retrylimit %d ms, retrylimit: under/over(%d/%d)",
					cfg.lb_mode, nbest_readers, nfb_readers, lbmaxreaders, readers_total, retrylimit, readers_under_retrylimit, readers_over_retrylimit);

	/*
	 * Count available readers, prefill some needed stats in case no stats, also
	 * make all readers inactive by default so it will be activated later.
	 * Remove all best marked readers first, than premark only valid readers.
	 * Skip cacheex=1 readers.
	 */
	for (ea = er->matching_rdr; ea; ea = ea->next)
	{
		rdr = ea->reader;

		if (rdr == NULL)
		{
			continue;
		}

		if (!er->reader_avail)
		{
			continue;
		}

#ifdef CS_CACHEEX
		// if cacheex reader, always active and no stats
		if (rdr->cacheex.mode == 1)
		{
			ea->status |= READER_ACTIVE;
			continue;
		}
#endif

		// Deactivate reader fist and reset things
		ea->status &= ~(READER_ACTIVE | READER_FALLBACK);
		ea->value = 0;
		ea->lb_best_marked = 0;
		readers_total += 1;

		s = get_stat(rdr, &q);

		if (s == NULL)
		{
			continue;
		}

		/*
		 * temporary mark all E_FOUND readers which is under ecm count.
		 * we doing premark first, 0xee = under, 0xff = over
		 * later we will do final mark, U = under, O = over, F = under (fallback), G = over (fallback)
		 */
		if (s->time_avg && retrylimit)
		{
			if (s->rc == E_FOUND && s->time_avg <= retrylimit && s->ecm_count >= cfg.lb_min_ecmcount && s->ecm_count <= cfg.lb_max_ecmcount)
			{
				readers_under_retrylimit += 1;
				ea->lb_best_marked = 0xee;
			}

			if (s->rc == E_FOUND && s->time_avg > retrylimit && s->ecm_count >= cfg.lb_min_ecmcount && s->ecm_count <= cfg.lb_max_ecmcount)
			{
				readers_over_retrylimit += 1;
				ea->lb_best_marked = 0xff;
			}
		}
		else
		{
			cs_log_dbg(D_LB, "loadbalancer: reader %s is not premarked, without (time_avg: %d and retrylimit: %d) dependency!", rdr->label, s->time_avg, retrylimit);
		}
	}

	// Now recalculate things
	if (nbest_readers >= readers_total)
	{
		nbest_readers = readers_total;
		nfb_readers = 0; // no space for nfb readers!
	}

	// In case there is some space for nfb, correct it.
	if (nfb_readers > 0)
	{
		if (nfb_readers + nbest_readers >= readers_total)
		{
			nfb_readers = readers_total - nbest_readers;
		}
	}

	// change lb_max_readers to curently available readers.
	lbmaxreaders = readers_total;

	cs_log_dbg(D_LB, "loadbalancer: Recalculated configuration: lb_mode %d, lb_nbest_readers %d, lb_nfb_readers %d, lb_max_readers %d, matching readers %d, lb_retrylimit %d ms, retrylimit: under/over(%d/%d)",
					cfg.lb_mode, nbest_readers, nfb_readers, lbmaxreaders, readers_total, retrylimit, readers_under_retrylimit, readers_over_retrylimit);

#ifdef WITH_DEBUG
	if (cs_dblevel & D_LB)
	{
		char *ecmbuf = NULL;

		if (cs_malloc(&ecmbuf, ECM_FMT_LEN))
		{
			format_ecm(er, ecmbuf, ECM_FMT_LEN);
			cs_log_dbg(D_LB, "loadbalancer: Client: %s, requested for: %s", username(er->client), ecmbuf);
			free(ecmbuf);
		}
	}
#endif

	/*
	 * Final marking. Here we mark the best under retrylimit readers based on lb_mode.
	 */
	while(readers_under_retrylimit > 0)
	{
		// keep the best matching reader node_id here
		uint8_t *matched_unique_id = NULL;

		if (!cs_malloc(&matched_unique_id, 8))
		{
			break;
		}

		for (ea = er->matching_rdr; ea; ea = ea->next)
		{
			int32_t weight;

			// skip those not marked
			if (ea->lb_best_marked != 0xee)
			{
				continue;
			}

			rdr = ea->reader;

			if (rdr == NULL)
			{
				continue;
			}

			if (!er->reader_avail)
			{
				continue;
			}

			s = get_stat(rdr, &q);

			if (s == NULL)
			{
				continue;
			}

			weight = (rdr->lb_weight <= 0) ? 100 : rdr->lb_weight;

			switch(cfg.lb_mode)
			{
				case LB_FASTEST_READER_FIRST:
					current = s->time_avg * 100 / weight;

					// if no prev_current stored
					if (prev_current == -1)
					{
						prev_current = current;
					}

					// Priority have reader with the best ecm time
					if (current <= prev_current)
					{
						memcpy(matched_unique_id, rdr->unique_id, 8);
					}

					prev_current = current;
					break;

				case LB_OLDEST_READER_FIRST:
					if (!rdr->lb_last.time || !rdr->lb_last.millitm)
					{
						cs_ftimeus(&check_time);
						rdr->lb_last = check_time;
					}

					current = rdr->lb_last.time;

					// if no prev_currentus stored
					if (prev_current == -1)
					{
						prev_current = current;
					}

					// if no prev_currentus stored
					if (prev_currentus == -1)
					{
						prev_currentus = rdr->lb_last.millitm;
					}

					/*
					 * Priority have reader used longest time ago. That mean
					 * lower timestamp indicate longest time ago.
					 */
					if (current <= prev_current)
					{
						if (current < prev_current)
						{
							// mark imediatelly
							memcpy(matched_unique_id, rdr->unique_id, 8);
						}
						else
						{
							// current == prev_current, in that case we need to compare microtime
							if (rdr->lb_last.millitm <= prev_currentus)
							{
								memcpy(matched_unique_id, rdr->unique_id, 8);
							}
						}
					}

					prev_current = current;
					prev_currentus = rdr->lb_last.millitm;
					break;

				case LB_LOWEST_USAGELEVEL:
					current = rdr->lb_usagelevel * 100 / weight;

					// if no prev_currentus stored
					if (prev_current == -1)
					{
						prev_current = current;
					}

					if (current <= prev_current)
					{
						memcpy(matched_unique_id, rdr->unique_id, 8);
					}

					prev_current = current;
					break;
			}

#if defined(WEBIF) || defined(LCDSUPPORT)
			rdr->lbvalue = llabs(s->time_avg * 100 / weight);
#endif
			ea->value = current;
			ea->time = s->time_avg;

			cs_log_dbg(D_LB, "loadbalancer: reader %s (under retrylimit search debug), unique_id: %s, lbvalue: %lld, time-avg: %d, current: %lld, current_us: %lld, ecm_count: %d",
						 rdr->label, rdr->unique_id, llabs(s->time_avg * 100 / weight), s->time_avg, current, prev_currentus, s->ecm_count);
		}

		if (matched_unique_id[0] != '\0')
		{
			for (ea = er->matching_rdr; ea; ea = ea->next)
			{
				rdr = ea->reader;

				if (rdr == NULL)
				{
					continue;
				}

				if (!er->reader_avail)
				{
					continue;
				}

				s = get_stat(rdr, &q);

				if (s == NULL)
				{
					continue;
				}

				if (memcmp(rdr->unique_id, matched_unique_id, 8) == 0)
				{
					// mark nbest reader
					if (bsm < nbest_readers)
					{
						ea->lb_best_marked = 'U';
						bsm += 1;

						cs_log_dbg(D_LB, "loadbalancer: reader %s (under retrylimit MARKED), unique_id: %s, time-avg: %d, current: %lld, ecm_count: %d",
							 		rdr->label, rdr->unique_id, s->time_avg, prev_current, s->ecm_count);
					}
					else
					{
						// mark fallback reader
						if (fbm < nfb_readers)
						{
							ea->lb_best_marked = 'F';
							fbm += 1;

							cs_log_dbg(D_LB, "loadbalancer: reader %s (under retrylimit FB MARKED), unique_id: %s, time-avg: %d, current: %lld, ecm_count: %d",
							 			rdr->label, rdr->unique_id, s->time_avg, prev_current, s->ecm_count);
						}
					}

					break;
				}
			}
		}

		free(matched_unique_id);
		readers_under_retrylimit -= 1;

	}

	/*
	 * Final marking. Here we mark the best over retrylimit readers based on lb_mode.
	 */
	while(readers_over_retrylimit > 0)
	{
		// keep the best matching reader node_id here
		uint8_t *matched_unique_id = NULL;

		if (!cs_malloc(&matched_unique_id, 8))
		{
			break;
		}

		for (ea = er->matching_rdr; ea; ea = ea->next)
		{
			int32_t weight;

			// skip those not marked
			if (ea->lb_best_marked != 0xff)
			{
				continue;
			}

			rdr = ea->reader;

			if (rdr == NULL)
			{
				continue;
			}

			if (!er->reader_avail)
			{
				continue;
			}

			s = get_stat(rdr, &q);

			if (s == NULL)
			{
				continue;
			}

			weight = (rdr->lb_weight <= 0) ? 100 : rdr->lb_weight;

			switch(cfg.lb_mode)
			{
				case LB_FASTEST_READER_FIRST:
					current = s->time_avg * 100 / weight;

					// if no prev_current stored
					if (prev_current == -1)
					{
						prev_current = current;
					}

					// Priority have reader with the best ecm time
					if (current <= prev_current)
					{
						memcpy(matched_unique_id, rdr->unique_id, 8);
					}

					prev_current = current;
					break;

				case LB_OLDEST_READER_FIRST:
					if (!rdr->lb_last.time || !rdr->lb_last.millitm)
					{
						cs_ftimeus(&check_time);
						rdr->lb_last = check_time;
					}

					current = rdr->lb_last.time;

					// if no prev_currentus stored
					if (prev_current == -1)
					{
						prev_current = current;
					}

					// if no prev_currentus stored
					if (prev_currentus == -1)
					{
						prev_currentus = rdr->lb_last.millitm;
					}

					/*
					 * Priority have reader used longest time ago. That mean
					 * lower timestamp indicate longest time ago.
					 */
					if (current <= prev_current)
					{
						if (current < prev_current)
						{
							// mark imediatelly
							memcpy(matched_unique_id, rdr->unique_id, 8);
						}
						else
						{
							// current == prev_current, in that case we need to compare microtime
							if (rdr->lb_last.millitm <= prev_currentus)
							{
								memcpy(matched_unique_id, rdr->unique_id, 8);
							}
						}
					}

					prev_current = current;
					prev_currentus = rdr->lb_last.millitm;
					break;

				case LB_LOWEST_USAGELEVEL:
					current = rdr->lb_usagelevel * 100 / weight;

					// if no prev_currentus stored
					if (prev_current == -1)
					{
						prev_current = current;
					}

					if (current <= prev_current)
					{
						memcpy(matched_unique_id, rdr->unique_id, 8);
					}

					prev_current = current;
					break;
			}

#if defined(WEBIF) || defined(LCDSUPPORT)
			rdr->lbvalue = llabs(s->time_avg * 100 / weight);
#endif
			ea->value = current;
			ea->time = s->time_avg;

			cs_log_dbg(D_LB, "loadbalancer: reader %s (over retrylimit search debug), unique_id: %s, lbvalue: %lld, time-avg: %d, current: %lld, current_us: %lld, ecm_count: %d",
						 rdr->label, rdr->unique_id, llabs(s->time_avg * 100 / weight), s->time_avg, current, prev_currentus, s->ecm_count);
		}

		if (matched_unique_id[0] != '\0')
		{
			for (ea = er->matching_rdr; ea; ea = ea->next)
			{
				rdr = ea->reader;

				if (rdr == NULL)
				{
					continue;
				}

				if (!er->reader_avail)
				{
					continue;
				}

				s = get_stat(rdr, &q);

				if (s == NULL)
				{
					continue;
				}

				if (memcmp(rdr->unique_id, matched_unique_id, 8) == 0)
				{
					// mark nbest reader
					if (bsm < nbest_readers)
					{
						ea->lb_best_marked = 'O';
						bsm += 1;

						cs_log_dbg(D_LB, "loadbalancer: reader %s (over retrylimit MARKED), unique_id: %s, time-avg: %d, current: %lld, ecm_count: %d",
							 		rdr->label, rdr->unique_id, s->time_avg, prev_current, s->ecm_count);
					}
					else
					{
						// mark fallback reader
						if (fbm < nfb_readers)
						{
							ea->lb_best_marked = 'G';
							fbm += 1;

							cs_log_dbg(D_LB, "loadbalancer: reader %s (over retrylimit FB MARKED), unique_id: %s, time-avg: %d, current: %lld, ecm_count: %d",
							 			rdr->label, rdr->unique_id, s->time_avg, prev_current, s->ecm_count);
						}
					}

					break;
				}
			}
		}

		free(matched_unique_id);
		readers_over_retrylimit -= 1;
	}

	/*
	 * Activate readers with not enought ecm count or no stats.
	 * Reset statistics if reader exceed max ecm count.
	 * Activate prefer local cards readers.
	 * Activate nbest marked readers and take care to lb_nok_tolerance.
	 * Activate fallback readers.
	 */
	for (ea = er->matching_rdr; ea; ea = ea->next)
	{
		rdr = ea->reader;

		if (rdr == NULL)
		{
			continue;
		}

		if (!er->reader_avail)
		{
			continue;
		}

		s = get_stat(rdr, &q);

		// readers without stats must be active. (there is only one problem, those readers is outside lodbalance!)
		if (s == NULL)
		{
			// Readers with no stats must be activated & we not count them in readers_active!
			cs_log_dbg(D_LB, "loadbalancer: reader %s need starting statistics for caid:prid:srvid:chid(%04X:%06X:%04X:%04X) --> ACTIVE", rdr->label, q.caid, q.prid, q.srvid, q.chid);
			ea->status |= READER_ACTIVE;
			continue;
		}

		/*
		 * Activate reader if not reached min ecm count. We not increase readers_active count here
		 * because we need space for best marked readers! We unmark best marked with less ecm count
		 * than min ecm count.
		 */
		if (s->ecm_count < cfg.lb_min_ecmcount)
		{
			cs_log_dbg(D_LB, "loadbalancer: reader %s, ecm_count: %d, not reached lb_min_ecmcount: %d --> ACTIVE", rdr->label, s->ecm_count, cfg.lb_min_ecmcount);
			ea->status |= READER_ACTIVE;
			s->fail_factor = 0; // yes!
			ea->lb_best_marked = 0;
			continue;
		}

		/*
		 * We should reset reader stats in case max ecm count reached.
		 * We can't activate reader right now after we reset stats, will activate them later.
		 */
		if (s->ecm_count > cfg.lb_max_ecmcount)
		{
			cs_log_dbg(D_LB, "loadbalancer: reader %s, ecm_count: %d, reaches lb_max_ecmcount: %d, resetting statistics --> NOT ACTIVE", rdr->label, s->ecm_count, cfg.lb_max_ecmcount);
			reset_ecmcount_reader(s, rdr); // ecm_count=0
			reset_avgtime_reader(s, rdr); // time_avg=0
			s->fail_factor = 0; // yes!
			ea->lb_best_marked = 0;
			continue;
		}

		// just warn
		if (readers_active == nbest_readers)
		{
			cs_log_dbg(D_LB, "loadbalancer: reader %s reached nbest readers (%d) -> NOT ACTIVE", rdr->label, nbest_readers);
		}

		/*
		 * Prefer localcards flaged readers have priority!
		 * Activate best under marked local readers if there is some free space for more nbest readers
		 */
		if (ea->lb_best_marked == 'U' && s->fail_factor >= 0 && er->preferlocalcards && (ea->status & READER_LOCAL) && readers_active < nbest_readers)
		{
			tol_calc_f = ((s->fail_factor + 0.0) / (s->ecm_count + 0.0)) * 100.0;
			tol_calc = (uint32_t)(tol_calc_f * 1000 + 0.5);
			tol_calc = (tol_calc - (tol_calc % 1000)) / 1000;

			/*
			 * Threat reader with lb_nok_tolerance parameter
			 * ---------------------------------------------
			 * All those readers which exceed lb_nok_tolerance is blocked, if you need 100 percent ECM OK you should set lb_nok_tolerance to 100%
			 * but do in mind than if 1 NOK than reader will go blocked for lb_reopen_secconds time! So setup lb_nok_tolerance parameter
			 * per your like!
			 */
			if (tol_calc <= (uint32_t)cfg.lb_nok_tolerance)
			{
				ea->status |= READER_ACTIVE;

				cs_log_dbg(D_LB, "loadbalancer: reader: %s (under retrylimit, prefer local), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d (lb_nok_tolerance: %d) --> ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);

				readers_active += 1;
			}
			else
			{
				cs_log_dbg(D_LB, "loadbalancer: reader: %s (under retrylimit, prefer local), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d reached (lb_nok_tolerance: %d) --> NOT ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);
			}

			continue;
		}

		/*
		 * Prefer localcards flaged readers have priority!
		 * Activate best over marked local readers if there is some free space for more nbest readers
		 */
		if (ea->lb_best_marked == 'O' && s->fail_factor >= 0 && er->preferlocalcards && (ea->status & READER_LOCAL) && readers_active < nbest_readers)
		{
			tol_calc_f = ((s->fail_factor + 0.0) / (s->ecm_count + 0.0)) * 100.0;
			tol_calc = (uint32_t)(tol_calc_f * 1000 + 0.5);
			tol_calc = (tol_calc - (tol_calc % 1000)) / 1000;

			/*
			 * Threat reader with lb_nok_tolerance parameter
			 * ---------------------------------------------
			 * All those readers which exceed lb_nok_tolerance is blocked, if you need 100 percent ECM OK you should set lb_nok_tolerance to 100%
			 * but do in mind than if 1 NOK than reader will go blocked for lb_reopen_secconds time! So setup lb_nok_tolerance parameter
			 * per your like!
			 */
			if (tol_calc <= (uint32_t)cfg.lb_nok_tolerance)
			{
				ea->status |= READER_ACTIVE;

				cs_log_dbg(D_LB, "loadbalancer: reader: %s (over retrylimit, prefer local), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d (lb_nok_tolerance: %d) --> ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);

				readers_active += 1;
			}
			else
			{
				cs_log_dbg(D_LB, "loadbalancer: reader: %s (over retrylimit, prefer local), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d reached (lb_nok_tolerance: %d) --> NOT ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);
			}

			continue;
		}

		// Activate best under marked readers if there is some free space for more nbest readers
		if (ea->lb_best_marked == 'U' && s->fail_factor >= 0 && readers_active < nbest_readers)
		{
			tol_calc_f = ((s->fail_factor + 0.0) / (s->ecm_count + 0.0)) * 100.0;
			tol_calc = (uint32_t)(tol_calc_f * 1000 + 0.5);
			tol_calc = (tol_calc - (tol_calc % 1000)) / 1000;

			/*
			 * Threat reader with lb_nok_tolerance parameter
			 * ---------------------------------------------
			 * All those readers which exceed lb_nok_tolerance is blocked, if you need 100 percent ECM OK you should set lb_nok_tolerance to 100%
			 * but do in mind than if 1 NOK than reader will go blocked for lb_reopen_secconds time! So setup lb_nok_tolerance parameter
			 * per your like!
			 */
			if (tol_calc <= (uint32_t)cfg.lb_nok_tolerance)
			{
				ea->status |= READER_ACTIVE;

				cs_log_dbg(D_LB, "loadbalancer: reader: %s (under retrylimit), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d (lb_nok_tolerance: %d) --> ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);

				readers_active += 1;
			}
			else
			{
				cs_log_dbg(D_LB, "loadbalancer: reader: %s (under retrylimit), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d reached (lb_nok_tolerance: %d) --> NOT ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);
			}

			continue;
		}

		// Activate best over marked readers if there is some free space for more nbest readers
		if (ea->lb_best_marked == 'O' && s->fail_factor >= 0 && readers_active < nbest_readers)
		{
			tol_calc_f = ((s->fail_factor + 0.0) / (s->ecm_count + 0.0)) * 100.0;
			tol_calc = (uint32_t)(tol_calc_f * 1000 + 0.5);
			tol_calc = (tol_calc - (tol_calc % 1000)) / 1000;

			/*
			 * Threat reader with lb_nok_tolerance parameter
			 * ---------------------------------------------
			 * All those readers which exceed lb_nok_tolerance is blocked, if you need 100 percent ECM OK you should set lb_nok_tolerance to 100%
			 * but do in mind than if 1 NOK than reader will go blocked for lb_reopen_secconds time! So setup lb_nok_tolerance parameter
			 * per your like!
			 */
			if (tol_calc <= (uint32_t)cfg.lb_nok_tolerance)
			{
				ea->status |= READER_ACTIVE;

				cs_log_dbg(D_LB, "loadbalancer: reader: %s (over retrylimit), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d (lb_nok_tolerance: %d) --> ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);

				readers_active += 1;
			}
			else
			{
				cs_log_dbg(D_LB, "loadbalancer: reader: %s (over retrylimit), ecmcount: %d (min=%d, max=%d), fail_factor: %d, time-avg: %d, tolerance: %d reached (lb_nok_tolerance: %d) --> NOT ACTIVE",
									 rdr->label, s->ecm_count, cfg.lb_min_ecmcount, cfg.lb_max_ecmcount, s->fail_factor, s->time_avg, tol_calc, cfg.lb_nok_tolerance);
			}

			continue;
		}

		/*
		 * Fallbacks readers
		 * ------------------
		 * Select fallbacks readers priority:
		 * 1. forced (lb_force_fallback=1) fixed fallback
		 * 2. "normal" fixed fallback
		 * 3. best ea->value remaining reader
		 */

		// Check for fixed fallbacks
		int32_t n_fixed_fb = chk_has_fixed_fallback(er);

		// Check first for lb_force_fallback=1 readers. No need stats!
		if (chk_is_fixed_fallback(rdr, er) && rdr->lb_force_fallback && n_fixed_fb && nfb_readers)
		{
			ea->status |= (READER_ACTIVE | READER_FALLBACK);
			cs_log_dbg(D_LB, "loadbalancer: reader %s (FIXED with force) --> FALLBACK", rdr->label);
			nfb_readers -= 1;
			fb_readers_active += 1;
			continue;
		}

		// Check for "normal" fixed fallback
		if (s->rc == E_FOUND && chk_is_fixed_fallback(rdr, er) && !rdr->lb_force_fallback && n_fixed_fb && nfb_readers)
		{
			ea->status |= (READER_ACTIVE | READER_FALLBACK);
			cs_log_dbg(D_LB, "loadbalancer: reader %s (FIXED) --> FALLBACK", rdr->label);
			nfb_readers -= 1;
			fb_readers_active += 1;
			continue;
		}

		// Mark the rest best readers as a fallback (under retrylimit marked) if there is a free space
		if (s->rc == E_FOUND && ea->lb_best_marked == 'F' && nfb_readers)
		{
			ea->status |= (READER_ACTIVE | READER_FALLBACK);
			cs_log_dbg(D_LB, "loadbalancer: reader %s (under retrylimit) --> FALLBACK", rdr->label);
			nfb_readers -= 1;
			fb_readers_active += 1;
		}

		// Mark the rest best readers as a fallback (over retrylimit marked) if there is a free space
		if (s->rc == E_FOUND && ea->lb_best_marked == 'G' && nfb_readers)
		{
			ea->status |= (READER_ACTIVE | READER_FALLBACK);
			cs_log_dbg(D_LB, "loadbalancer: reader %s (over retrylimit) --> FALLBACK", rdr->label);
			nfb_readers -= 1;
			fb_readers_active += 1;
		}
	}

	// In case no active readers we need to force reopen all the readers
	if (readers_active == 0 && fb_readers_active == 0)
	{
		cs_log_dbg(D_LB, "loadbalancer: NO VALID MATCHING READER FOUND!");
		force_reopen = 1;
	}

	// Here we can try to reopen blocked nbest readers; if force_reopen=1, force reopen blocked readers!
	try_open_blocked_readers(er, &q, nbest_readers, force_reopen);

	cs_log_dbg(D_LB, "loadbalancer: --------------------------------------------");

	return;
}

/**
 * clears statistic of reader ridx.
 **/
void clear_reader_stat(struct s_reader *rdr)
{
	if (rdr == NULL)
	{
		return;
	}
	else
	{
		if (rdr->lb_stat == NULL)
		{
			return;
		}

		ll_clear_data(rdr->lb_stat);
	}
}

void clear_all_stat(void)
{
	struct s_reader *rdr = NULL;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		clear_reader_stat(rdr);
	}
}

static void housekeeping_stat_thread(void)
{
	struct timeb now;
	cs_ftime(&now);
	int32_t cleanup_timeout = cfg.lb_stat_cleanup * 60 * 60 * 1000;
	int32_t cleaned = 0;
	struct s_reader *rdr;
	set_thread_name(__func__);
	LL_ITER itr = ll_iter_create(configured_readers);

	cs_readlock(__func__, &readerlist_lock); // this avoids cleaning a reading during writing

	while((rdr = ll_iter_next(&itr)))
	{
		if(rdr->lb_stat)
		{
			rdr->lb_stat_busy = 1;
			cs_writelock(__func__, &rdr->lb_stat_lock);

			LL_ITER it = ll_iter_create(rdr->lb_stat);
			READER_STAT *s;

			while((s = ll_iter_next(&it)))
			{
				int64_t gone = comp_timeb(&now, &s->last_received);
				if(gone > cleanup_timeout)
				{
					ll_iter_remove_data(&it);
					cleaned++;
				}
			}

			cs_writeunlock(__func__, &rdr->lb_stat_lock);
			rdr->lb_stat_busy = 0;
		}
	}

	cs_readunlock(__func__, &readerlist_lock);

	cs_log_dbg(D_LB, "loadbalancer cleanup: removed %d entries", cleaned);
}

static void housekeeping_stat(int32_t force)
{
	struct timeb now;
	cs_ftime(&now);
	int64_t gone = comp_timeb(&now, &last_housekeeping);
	if(!force && (gone < 60 * 60 * 1000)) // only clean once in an hour
		{ return; }

	last_housekeeping = now;
	start_thread("housekeeping lb stats", (void *)&housekeeping_stat_thread, NULL, NULL, 1, 1);
}

static int compare_stat(READER_STAT **ps1, READER_STAT **ps2)
{
	READER_STAT *s1 = (*ps1), *s2 = (*ps2);
	int64_t res = s1->rc - s2->rc;
	if(res) { return res; }
	res = s1->caid - s2->caid;
	if(res) { return res; }
	res = s1->prid - s2->prid;
	if(res) { return res; }
	res = s1->srvid - s2->srvid;
	if(res) { return res; }
	res = s1->chid - s2->chid;
	if(res) { return res; }
	res = s1->ecmlen - s2->ecmlen;
	if(res) { return res; }
	res = comp_timeb(&s1->last_received, &s2->last_received);
	return res;
}

static int compare_stat_r(READER_STAT **ps1, READER_STAT **ps2)
{
	return -compare_stat(ps1, ps2);
}

READER_STAT **get_sorted_stat_copy(struct s_reader *rdr, int32_t reverse, int32_t *size)
{
	if(reverse)
		{ return (READER_STAT **)ll_sort(rdr->lb_stat, compare_stat_r, size); }
	else
		{ return (READER_STAT **)ll_sort(rdr->lb_stat, compare_stat, size); }
}

static int8_t stat_in_ecmlen(struct s_reader *rdr, READER_STAT *s)
{
	int32_t i = 0;

	if (rdr == NULL || s == NULL)
	{
		return i;
	}

	for (i=0; i < rdr->ecm_whitelist.ewnum; i++)
	{
		ECM_WHITELIST_DATA *d = &rdr->ecm_whitelist.ewdata[i];
		if ((d->caid == 0 || d->caid == s->caid) && (d->ident == 0 || d->ident == s->prid) && (d->len == s->ecmlen))
		{
			return 1;
		}
	}

	return 0;
}

static int8_t add_to_ecmlen(struct s_reader *rdr, READER_STAT *s)
{
	int32_t i = 0;

	if (rdr == NULL || s == NULL)
	{
		return i;
	}

	for (i=0; i < rdr->ecm_whitelist.ewnum; i++)
	{
		ECM_WHITELIST_DATA *d = &rdr->ecm_whitelist.ewdata[i];
		if ((d->caid == s->caid) && (d->ident == s->prid) && (d->len == s->ecmlen))
			return 1;
	}

	ECM_WHITELIST_DATA d = { .caid = s->caid, .ident = s->prid, .len = s->ecmlen };
	ecm_whitelist_add(&rdr->ecm_whitelist, &d);

	return 0;
}

void update_ecmlen_from_stat(struct s_reader *rdr)
{
	if (rdr == NULL)
	{
		return;
	}
	else
	{
		if (rdr->lb_stat == NULL)
		{
			return;
		}

		cs_readlock(__func__, &rdr->lb_stat_lock);

		LL_ITER it = ll_iter_create(rdr->lb_stat);
		READER_STAT *s = NULL;

		while((s = ll_iter_next(&it)))
		{
			if (s->rc == E_FOUND)
			{
				if (!stat_in_ecmlen(rdr, s))
				{
					add_to_ecmlen(rdr, s);
				}
			}
		}

		cs_readunlock(__func__, &rdr->lb_stat_lock);
	}
}

/**
 * mark as last reader after checked for cache requests:
 **/
void lb_mark_last_reader(ECM_REQUEST *er)
{
	if (er == NULL)
	{
		return;
	}

	// OLDEST_READER: set lb_last
	struct s_ecm_answer *ea = NULL;
	for(ea = er->matching_rdr; ea; ea = ea->next)
	{
		if ((ea->status & (READER_ACTIVE | READER_FALLBACK)) == READER_ACTIVE)
		{
			cs_ftimeus(&ea->reader->lb_last);
		}
	}
}

/**
 * Automatic timeout feature depending on statistik values
 **/
static uint32_t __lb_auto_timeout(ECM_REQUEST *er, uint32_t ctimeout)
{
	STAT_QUERY q;
	READER_STAT *s = NULL;
	struct s_reader *rdr = NULL;
	struct s_ecm_answer *ea = NULL;

	if (er == NULL)
	{
		return ctimeout;
	}

	for (ea = er->matching_rdr; ea; ea = ea->next)
	{
		if ((ea->status & (READER_ACTIVE | READER_FALLBACK)) == READER_ACTIVE)
		{
			rdr = ea->reader;
			get_stat_query(er, &q);
			s = get_stat(rdr, &q);
			if (s)
			{
				break;
			}
		}
	}

	if (s == NULL)
	{
		return ctimeout;
	}

	uint32_t t;
	if (s->rc == E_TIMEOUT)
	{
		// timeout known, early timeout!
		t = ctimeout / 2;
	}
	else
	{
		if (s->ecm_count < cfg.lb_min_ecmcount)
		{
			return ctimeout;
		}

		t = s->time_avg * (100 + cfg.lb_auto_timeout_p) / 100;

		if ((int32_t)(t - s->time_avg) < cfg.lb_auto_timeout_t)
		{
			t = s->time_avg + cfg.lb_auto_timeout_t;
		}
	}

	if (t > ctimeout)
	{
		t = ctimeout;
	}

#ifdef WITH_DEBUG
	if (D_TRACE & cs_dblevel)
	{
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_log_dbg(D_TRACE, "auto-timeout for %s %s set rdr %s to %d", username(er->client), buf, rdr->label, t);
	}
#endif
	return t;
}

uint32_t lb_auto_timeout(ECM_REQUEST *er, uint32_t timeout)
{
	if (er == NULL)
	{
		return timeout;
	}
	else
	{
		if (cfg.lb_auto_timeout)
		{
			return __lb_auto_timeout(er, timeout);
		}
	}

	return timeout;
}

bool lb_check_auto_betatunnel(ECM_REQUEST *er, struct s_reader *rdr)
{
	bool match = 0;
	uint16_t caid = 0;

	if (!cfg.lb_auto_betatunnel || er == NULL || rdr == NULL)
	{
		return match;
	}

	caid = __lb_get_betatunnel_caid_to(er->caid);

	if (caid)
	{
		uint16_t save_caid = er->caid;
		er->caid = caid;
		match = matching_reader(er, rdr); // matching
		er->caid = save_caid;
	}

	return match;
}

/**
 * search for same ecm hash with same readers
 **/
static struct ecm_request_t *check_same_ecm(ECM_REQUEST *er)
{
	struct ecm_request_t *ecm = NULL;
	time_t timeout;
	struct s_ecm_answer *ea_ecm = NULL;
	struct s_ecm_answer *ea_er = NULL;
	uint8_t rdrs = 0;

	if (er == NULL)
	{
		return NULL;
	}

	cs_readlock(__func__, &ecmcache_lock);

	for (ecm = ecmcwcache; ecm; ecm = ecm->next)
	{
		timeout = time(NULL) - ((cfg.ctimeout + 500) / 1000);

		if (ecm->tps.time <= timeout)
		{
			break;
		}

		if (ecm == er)
		{
			continue;
		}

		if (er->caid != ecm->caid || memcmp(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
		{
			continue;
		}

		if (!er->readers || !ecm->readers || er->readers != ecm->readers)
		{
			continue;
		}

		ea_ecm = ecm->matching_rdr;
		ea_er = er->matching_rdr;
		rdrs = er->readers;

		while(rdrs && ea_ecm && ea_er)
		{
			if (ea_ecm->reader != ea_er->reader)
			{
				break;
			}
			ea_ecm = ea_ecm->next;
			ea_er = ea_er->next;
			rdrs--;
		}

		if (!rdrs)
		{
			cs_readunlock(__func__, &ecmcache_lock);
			return ecm;
		}
	}

	cs_readunlock(__func__, &ecmcache_lock);

	return NULL; // nothing found so return null
}

static void use_same_readers(ECM_REQUEST *er_new, ECM_REQUEST *er_cache)
{
	if (er_new == NULL || er_cache == NULL)
	{
		return;
	}
	else
	{
		struct s_ecm_answer *ea_new = er_new->matching_rdr;
		struct s_ecm_answer *ea_cache = er_cache->matching_rdr;
		uint8_t rdrs = er_new->readers;

		while(rdrs)
		{
			ea_new->status &= ~(READER_ACTIVE | READER_FALLBACK);
			if ((ea_cache->status & READER_ACTIVE))
			{
				if (!(ea_cache->status & READER_FALLBACK))
				{
					ea_new->status |= READER_ACTIVE;
				}
				else
				{
					ea_new->status |= (READER_ACTIVE | READER_FALLBACK);
				}
			}

			ea_new = ea_new->next;
			ea_cache = ea_cache->next;
			rdrs--;
		}
	}
}

void lb_set_best_reader(ECM_REQUEST *er)
{
	if (!cfg.lb_mode || er == NULL)
	{
		return;
	}

	// cache2 is handled by readers queue, so, if a same ecm hash with same readers, use these same readers to get cache2 from them! Not ask other readers!
	struct ecm_request_t *ecm_eq = NULL;
	ecm_eq = check_same_ecm(er);

	if (ecm_eq)
	{
		// set all readers used by ecm_eq, so we get cache2 from them!
		use_same_readers(er, ecm_eq);
		cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] found same ecm with same readers from client %s, use them!", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, (check_client(ecm_eq->client) ? ecm_eq->client->account->usr : "-"));
	}
	else
	{
		// FILTER readers by loadbalancing
		stat_get_best_reader(er);
	}
}

void lb_update_last(struct s_ecm_answer *ea_er, struct s_reader *reader)
{
	if (ea_er == NULL || reader == NULL)
	{
		return;
	}
	else
	{
		// for lb oldest reader mode - not use for fallback readers
		if (!(ea_er->status & READER_FALLBACK))
		{
			cs_ftimeus(&reader->lb_last);
		}
	}
}

void send_reader_stat(struct s_reader *rdr, ECM_REQUEST *er, struct s_ecm_answer *ea, int8_t rc)
{
	if (rdr == NULL || er == NULL || ea == NULL)
	{
		return;
	}
	else
	{
		if (rc >= E_99 || cacheex_reader(rdr))
		{
			return;
		}

		int32_t ecm_time = cfg.ctimeout;

		if (ea->ecm_time && ea->rc <= E_NOTFOUND)
		{
			ecm_time = ea->ecm_time;
		}

		add_stat(rdr, er, ecm_time, rc, ea->rcEx);
	}
}

void stat_finish(void)
{
	if (cfg.lb_mode && cfg.lb_save)
	{
		save_stat_to_file(0);

		if (cfg.lb_savepath)
		{
			cs_log("stats saved to file %s", cfg.lb_savepath);
		}

		// this is for avoiding duplicate saves
		cfg.lb_save = 0;
	}
}

#endif
