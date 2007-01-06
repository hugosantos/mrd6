#ifndef _support_lists_h_
#define _support_lists_h_

struct list_node {
	struct list_node *next;
};

struct dlist_node {
	struct dlist_node *prev, *next;
};

#define container_of(ptr, type, member) \
	((type *)(((char *)ptr) - offsetof(type, member)))

template<typename T>
static inline void list_push_front(T * &lst, T *node) {
	node->next = lst;
	lst = node;
}

template<typename T>
static inline T *list_pop_front(T * &lst) {
	if (!lst)
		return 0;
	T *head = lst;
	lst = lst->next;
	return head;
}

template<typename T>
static inline void list_insert_after(T * &lst, T *prev, T *node) {
	if (prev) {
		node->next = prev->next;
		prev->next = node;
	} else {
		node->next = lst;
		lst = node;
	}
}

template<typename T>
static inline bool list_search_remove(T * &lst, T *node) {
	T *prev = 0;

	for (T *curr = lst; curr; curr = curr->next) {
		if (curr == node) {
			/* unlink the node from the list */
			if (prev)
				prev->next = curr->next;
			else
				lst = curr->next;
			return true;
		}

		prev = curr;
	}

	return false;
}

template<typename T>
static inline void dlist_push_front(T * &lst, T *node) {
	node->prev = 0;
	if (lst)
		lst->prev = node;
	node->next = lst;
	lst = node;
}

template<typename T>
static inline T *dlist_pop_front(T * &lst) {
	if (!lst)
		return 0;

	T *head = lst;

	lst = lst->next;
	if (lst)
		lst->prev = 0;

	return head;
}

template<typename T>
static inline void list_remove(T * &node) {
	list_pop_front(node);
}

template<typename T>
static inline void dlist_remove(T * &lst, T *node) {
	if (!node->prev) {
		if (node->next) {
			node->next->prev = 0;
			lst = node->next;
		} else {
			lst = 0;
		}
	} else {
		node->prev->next = node->next;
		if (node->prev->next)
			node->prev->next->prev = node->prev;
	}
}

#endif

