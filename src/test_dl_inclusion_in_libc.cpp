int main(void)
{
	void *(*dlopen_fct)(const char *filename, int flag);
	char *(*dlerror_fct)(void);
	void *(*dlsym_fct)(void *handle, const char *symbol);
	int (*dlclose_fct)(void *handle);

	dlopen_fct = dlopen;
	dlerror_fct = dlerror;
	dlsym_fct = dlsym;
	dlclose_fct = dlclose;
	return 0;
}
