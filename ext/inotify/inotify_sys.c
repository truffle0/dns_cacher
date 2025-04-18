#include <ruby.h>
#include <ruby/io.h>
#include <ruby/intern.h>

#include <syscall.h>
#include <sys/inotify.h>

VALUE rb_inotify_create_fd(VALUE obj) {
	int fd = inotify_init();
	if (fd == -1) rb_sys_fail("Failed to allocate INotify fd");
	
	// Nothing special, just return the file descriptor	
	return INT2FIX(fd);
}

VALUE rb_inotify_add_watch_mask(VALUE obj, VALUE pathname, VALUE mask) {
	if (TYPE(pathname) != T_STRING || TYPE(mask) != T_FIXNUM) { 
		rb_raise(rb_eArgError, "Invalid argument");
	}
	
	// Retrieve file descriptor (and check it's still open)
	rb_io_t *fptr = RFILE(obj)->fptr;
	rb_io_check_closed(fptr);
	int fd = fptr->fd;
	
	// Convert args to ctypes and call inotify
	int watch_desc = inotify_add_watch(fd, RSTRING_PTR(pathname), NUM2INT(mask));

	if (watch_desc == -1) rb_sys_fail("Failed to add INotify watch");
	return INT2NUM(watch_desc);
}

VALUE rb_inotify_rm_watch_id(VALUE obj, VALUE watch) {
	if (TYPE(watch) != T_FIXNUM) {
		rb_raise(rb_eArgError, "Invalid argument types!");
	}

	// Retrieve file descriptor (and check it's still open)
	rb_io_t *fptr = RFILE(obj)->fptr;
	rb_io_check_closed(fptr);	
	int fd = fptr->fd;
	
	if (inotify_rm_watch(fd, NUM2INT(watch)) != 0) {
		rb_sys_fail("Failed to remove watch");
	}

	return Qnil;
}

VALUE rb_inotify_read(VALUE obj) {
	#define EVENT_MAX_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
	
	// Defer call to the standard IO#read function to actually IO
	// this is important to stop this function from waiting in
	// c-code potentially indefinitely when ruby has better things to do
	VALUE args[] = { INT2FIX(EVENT_MAX_SIZE) };
	VALUE rb_event = rb_call_super(1, args);

	//TODO: type and length checking
	
	// Type cast the data ruby string to an inotify_event struct
	struct inotify_event *event = (struct inotify_event *)StringValuePtr(rb_event);
	
	// Array the size of the inotify_event struct (without the len field)
	VALUE arr = rb_ary_new2(4);
	
	rb_ary_push(arr, INT2NUM(event->wd));
	rb_ary_push(arr, INT2NUM(event->mask));
	rb_ary_push(arr, INT2NUM(event->cookie));
	rb_ary_push(arr, rb_str_new(event->name, event->len));
	free(event);

	return arr;
}

VALUE rb_inotify_read_nonblock(VALUE obj) {
	// Retrieve file descriptor (and check it's still open)
	rb_io_t *fptr = RFILE(obj)->fptr;
	rb_io_check_closed(fptr);	
	int fd = fptr->fd;
	
	// Create a pollfd to check readability
	struct pollfd pol = { fd, POLLIN, 0};
	int ret = poll(&pol, 1, 0);

	if (ret == -1) rb_sys_fail("Poll error");
	if (ret == 0) rb_raise(rb_eIOTimeoutError, "Read timed out");

	#define EVENT_MAX_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)
	struct inotify_event *event = malloc(EVENT_MAX_SIZE);

	if (read(fd, event, EVENT_MAX_SIZE) == -1) {
		rb_sys_fail("Failed to read INotify FD");
	}
	
	// Array the size of the inotify_event struct (without the len field)
	VALUE arr = rb_ary_new2(4);
	
	rb_ary_push(arr, INT2NUM(event->wd));
	rb_ary_push(arr, INT2NUM(event->mask));
	rb_ary_push(arr, INT2NUM(event->cookie));
	rb_ary_push(arr, rb_str_new(event->name, event->len));
	free(event);

	return arr;
}

/* MASKS and supported event SYMBOLS */
typedef struct { const char* sym; int mask; } event_sym_t;
const event_sym_t event_sym_lookup[] = {
	{ "access", IN_ACCESS },
	{ "attrib", IN_ATTRIB },
	{ "close_write", IN_CLOSE_WRITE },
	{ "close_nowrite", IN_CLOSE_NOWRITE },
	{ "create", IN_CREATE },
	{ "delete", IN_DELETE },
	{ "delete_self", IN_DELETE_SELF },
	{ "modify", IN_MODIFY },
	{ "move_self", IN_MOVE_SELF },
	{ "moved_from", IN_MOVED_FROM },
	{ "moved_to", IN_MOVED_TO },
	{ "open", IN_OPEN },
};
#define N_INOTIFY_EVENTS (int)(sizeof(event_sym_lookup)/sizeof(event_sym_t))

VALUE rb_inotify_events2mask(VALUE obj, VALUE arr) {
	if (TYPE(arr) != T_ARRAY) {
		rb_raise(rb_eArgError, "Expecting Array of Symbols");
	}

	int mask = 0;
	for (int i = 0; i < rb_array_len(arr); i++) {
		VALUE sym = rb_ary_entry(arr, i);
		if (TYPE(sym) != T_SYMBOL) {
			rb_raise(rb_eArgError, "Non-symbol element found");
		}

		for (int j = 0; j < N_INOTIFY_EVENTS; j++) {
			if (SYM2ID(sym) == rb_intern(event_sym_lookup[j].sym)) {
				mask |= event_sym_lookup[j].mask;
				break;
			}
		}
	}

	return mask != 0 ? INT2NUM(mask) : Qnil;
}

VALUE rb_inotify_mask2events(VALUE obj, VALUE rb_mask) {
	if (TYPE(rb_mask) != T_FIXNUM) {
		rb_raise(rb_eArgError, "Expecting Integer");
	}

	int mask = FIX2INT(rb_mask);
	VALUE arr = rb_ary_new();

	for (int i = 0; i < N_INOTIFY_EVENTS; i++) {
		if (mask | event_sym_lookup[i].mask) {
			rb_ary_push(arr, ID2SYM(rb_intern(event_sym_lookup[i].sym)));
		}
	}

	return arr;
}

VALUE rb_inotify_supported_events() {
	VALUE arr = rb_ary_new2(N_INOTIFY_EVENTS);

	for (int i = 0; i < N_INOTIFY_EVENTS; i++) {
		event_sym_t ev = event_sym_lookup[i];
		rb_ary_push(arr, rb_to_symbol(rb_str_new2(ev.sym)));
	}

	return arr;
}

void Init_inotify_sys() {
	VALUE rb_cINotify = rb_define_class("INotify", rb_cIO);
	
	rb_define_private_method(rb_cINotify, "create_fd", rb_inotify_create_fd, 0);
	rb_define_private_method(rb_cINotify, "add_watch_mask", rb_inotify_add_watch_mask, 2);
	rb_define_private_method(rb_cINotify, "rm_watch_id", rb_inotify_rm_watch_id, 1);
	
	rb_define_method(rb_cINotify, "read", rb_inotify_read, 0);
	rb_define_method(rb_cINotify, "read_nonblock", rb_inotify_read_nonblock, 0);

	rb_define_private_method(rb_cINotify, "events2mask", rb_inotify_events2mask, 1);
	rb_define_private_method(rb_cINotify, "mask2events", rb_inotify_mask2events, 1);
	rb_define_const(rb_cINotify, "EVENTS", rb_inotify_supported_events());
}
