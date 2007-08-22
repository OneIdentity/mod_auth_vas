
SUBDIRS=	http-get .
DIST_SUBDIRS=	http-get

TESTS =

if ENABLE_RCDEV_TESTS
TESTS += \
	test.version \
	test.bug4286 \
	test.bug4712 \
	test.bug4713 \
	test.bug4784 \
	test.bug4833 \
	test.bug46 \
	test.bug47 \
	test.bug64 \
	test.bug167 \
	test.bug214 \
	test.bug337 \
	test.r203 \
	# end of tests
endif

TEST_PLATFORM = $(shell $(srcdir)/get-platform)
# Set environment variable DEBUG=true for test debugging
TESTS_ENVIRONMENT = $(SHELL) $(srcdir)/run-test $(TEST_PLATFORM)
EXTRA_DIST= get-platform run-test
