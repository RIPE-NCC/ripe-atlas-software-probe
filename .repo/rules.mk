# Set BRANCH

ifeq ($(GITLAB_CI),true)
	# In CI
	ifneq ($(CI_COMMIT_TAG),)
		# CI tag run
		BRANCH:=$(CI_COMMIT_TAG)
		# Does the tag start with a digit? (e.g. 5120)
		ifneq ($(filter 0% 1% 2% 3% 4% 5% 6% 7% 8% 9%,$(BRANCH)),)
			RELEASE:=master
		else
$(warning Unknown tag format. Typically starts with digit (e.g. 5120) and is master branch.)
		endif
	else ifneq ($(CI_COMMIT_BRANCH),)
		# CI branch run
		BRANCH:=$(CI_COMMIT_BRANCH)
	else
$(error ERROR: Running in CI, and there is no CI_COMMIT_TAG or CI_COMMIT_BRANCH.)
	endif
else
	# No CI - get branch manually
	BRANCH:=$(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
endif

# Set RELEASE based on Git branch

ifeq ($(BRANCH),master)
	RELEASE:=master
endif
ifneq ($(filter testing%,$(BRANCH)),) # testing, testing-hello, testing.hello2, ... are all valid
	RELEASE:=testing
endif
ifneq ($(filter devel%,$(BRANCH)),) # devel, devel-hello, devel.hello2, ... are all valid
	RELEASE:=devel
endif
ifeq ($(RELEASE),) # devel is a catch-all (e.g. unknown tags/branches)
$(warning Branch could not be matched with a release, defaulting to devel)
	RELEASE:=devel
endif

$(info Using BRANCH "$(BRANCH)")
$(info Using RELEASE "$(RELEASE)")
ifeq ($(BRANCH),)
$(error ERROR: No branch was matched)
else ifeq ($(RELEASE),)
$(error ERROR: No release was matched)
endif

# If the RELEASE is not master, we need to add something in the URL
# (...)/software-probe/.testing/ and (...)/software-probe/.devel/
ifneq ($(RELEASE),master)
REPO:=.$(RELEASE)/
else
REPO:=
endif

define fingerprint
$(shell gpg --list-packets $(1) | sed -nEe 's/^.*\(issuer fpr v4 ([0-9A-F]+)\)$$/\1/p')
endef

define keyid
$(shell gpg --list-packets $(1) | sed -nEe 's/^.*\(issuer key ID ([0-9A-F]+)\)$$/\1/p')
endef

define distribution
$(shell lsb_release -s -c 2>/dev/null)
endef

SUBST_KEYWORDS = sed \
             -e 's|@fingerprint[@]|$(FINGERPRINT)|g' \
             -e 's|@keyid[@]|$(KEYID)|g' \
             -e 's|@distribution[@]|$(DISTRIBUTION)|g' \
             -e 's|@repo[@]|$(REPO)|g' \
             -e 's|@release[@]|$(RELEASE)|g'

%.list:	%.list.in
	rm -f $@
	$(SUBST_KEYWORDS) $< > $@

%.pol:	%.pol.in
	rm -f $@
	$(SUBST_KEYWORDS) $< > $@

%.gpg:	%.gpg.asc
	rm -f $@
	gpg --dearmor < $< > $@
