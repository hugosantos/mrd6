#ifndef _support_refcount_h_
#define _support_refcount_h_

class refcountable {
public:
	refcountable();
	virtual ~refcountable();

	void grab();
	void release();

	int get_refcount() const;

protected:
	virtual void destructor();

private:
	int _refcount;
};

class auto_grab {
public:
	auto_grab(refcountable *_t) : t(_t) {
		t->grab();
	}

	~auto_grab() {
		if (t)
			t->release();
	}

private:
	refcountable *t;
};

inline refcountable::refcountable() : _refcount(0) {}
inline refcountable::~refcountable() { /* assert(_refcount == 0); */ }

inline void refcountable::grab() {
	_refcount ++;
}

inline void refcountable::release() {
	_refcount --;
	if (_refcount == 0)
		destructor();
}

inline int refcountable::get_refcount() const {
	return _refcount;
}

inline void refcountable::destructor() {
	delete this;
}

#endif

