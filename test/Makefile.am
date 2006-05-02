
SUBDIRS=	http-get .

TESTS = \
	test.version \
	test.bug4286 \
	test.bug4712 \
	test.bug4713 \
	test.bug4784 \
	test.bug4833 \
	# end of tests

TEST_PLATFORM = $(shell $(srcdir)/get-platform)
# Set environment variable DEBUG=true for test debugging
TESTS_ENVIRONMENT = $(SHELL) $(srcdir)/run-test $(TEST_PLATFORM)
EXTRA_DIST= get-platform run-test
