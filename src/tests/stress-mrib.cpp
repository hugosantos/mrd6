/*
 * stress_mrib - a simple module that when loaded will flood the
 *               MRIB with lots of prefixes. good to test responsiveness
 *               during install as well as memory usage.
 */

#include <mrd/mrd.h>
#include <mrd/mrib.h>

#include <mrd/support/objpool.h>

struct stress_prefix : mrib_def::prefix {
	stress_prefix(mrib_origin *owner)
		: mrib_def::prefix(owner) {}

	/* possible private data */
	uint8_t _space[16 + 8];
};

static objpool<stress_prefix> _stress_prefixes(256);

/* besides being a module, we also are a MRIB origin and an event sink */
class stress_mrib_module : public mrd_module, public mrib_origin, public event_sink {
public:
	stress_mrib_module(mrd *, void *);
	~stress_mrib_module();

	const char *description() const { return "stress-mrib"; }

	void return_prefix(mrib_def::prefix *p) {
		_stress_prefixes.return_obj((stress_prefix *)p);
	}

	bool check_startup();
	void shutdown();

	void event(int, void *);

	inet6_addr nh;
	int count;
	timeval start;
	double accum;
};

module_entry(stress_mrib, stress_mrib_module);

stress_mrib_module::stress_mrib_module(mrd *m, void *p)
	: mrd_module(m, p) {
	count = 0;
	accum = 0;
}

stress_mrib_module::~stress_mrib_module() {
}

bool stress_mrib_module::check_startup() {
	/* bogus nexthop, we dont care */
	if (!nh.set("2001:2002::3"))
		return false;

	gettimeofday(&start, 0);

	/* as soon as we are loaded, start the hammering */
	g_mrd->register_task(this, 0);

	return true;
}

void stress_mrib_module::shutdown() {
	/* on shutdown, clear all how MRIB damage */
	g_mrd->mrib().origin_lost(this);
}

void stress_mrib_module::event(int, void *) {
	/* dont install more than 500000 prefixes */
	if (count >= 500000) {
		timeval end;
		gettimeofday(&end, 0);

		uint32_t diff = (end.tv_sec - start.tv_sec) * 1000000;
		if (end.tv_usec > start.tv_usec)
			diff += end.tv_usec - start.tv_usec;
		else
			diff += 1000000 + end.tv_usec - start.tv_usec;

		g_mrd->log().info(QUIET) << "[STRESS] Took " << accum << "us to install " << count << " (real " << diff << "us)"
				<< " prefixes, " << (accum / (double)count) << "us per prefix in average" << endl;
		return;
	}

	count++;

	/* generate a random prefix */
	inet6_addr p;

	for (int i = 0; i < 4; i++)
		p.addr.s6_addr32[i] = rand();

	/* with a random prefix len 10-96 */
	p.prefixlen = 10 + rand() % 87;

	p.apply_prefixlen();

	stress_prefix *pr = _stress_prefixes.request_obj(this);
	if (pr) {
		pr->distance = rand() % 100;
		pr->metric = rand() % 10000;
		pr->nexthop = nh;
		pr->intf = 0;

		timeval ts, te;

		gettimeofday(&ts, 0);

		/* install the prefix with random metric */
		g_mrd->mrib().install_prefix(p, pr);

		gettimeofday(&te, 0);

		uint32_t diff = (te.tv_sec - ts.tv_sec) * 1000000;
		if (te.tv_usec > ts.tv_usec)
			diff += te.tv_usec - ts.tv_usec;
		else
			diff += (1000000 + te.tv_usec - ts.tv_usec);

		accum += diff;
	} else {
		_stress_prefixes.return_obj(pr);
		g_mrd->log().info(QUIET) << "[STRESS] failed to add prefix " << p << endl;
	}

	/* keep hammering */
	g_mrd->register_task(this, 0);
}

