
SUBDIRS=	http-get .
DIST_SUBDIRS=	http-get

TESTS =

if ENABLE_RCDEV_TESTS
TESTS += $(RCDEV_TESTS)
endif

RCDEV_TESTS = \
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
	test.bug370 \
	test.bug450 \
	test.bug385 \
	test.bug496 \
	test.bug369 \
	test.bug482 \
	# end of RCDEV tests

EXTRA_DIST= get-platform run-test $(RCDEV_TESTS)
