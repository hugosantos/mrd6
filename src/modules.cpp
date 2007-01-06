#include <mrd/mrd.h>

extern "C" mrd_module *mrd_module_init_mld(void *, mrd *);
extern "C" mrd_module *mrd_module_init_pim(void *, mrd *);
extern "C" mrd_module *mrd_module_init_bgp(void *, mrd *);
extern "C" mrd_module *mrd_module_init_console(void *, mrd *);

void mrd::add_static_modules() {
#ifdef MRD_STATIC_MLD
	m_static_modules["mld"] = &mrd_module_init_mld;
#endif

#ifdef MRD_STATIC_PIM
	m_static_modules["pim"] = &mrd_module_init_pim;
#endif

#ifdef MRD_STATIC_BGP
	m_static_modules["bgp"] = &mrd_module_init_bgp;
#endif

#ifdef MRD_STATIC_CONSOLE
	m_static_modules["console"] = &mrd_module_init_console;
#endif
}

