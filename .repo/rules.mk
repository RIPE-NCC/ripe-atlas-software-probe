# Try and default to GitLab CI/CD variables
BRANCH:=$(CI_COMMIT_TAG)
ifeq ($(BRANCH),)
BRANCH:=$(CI_COMMIT_BRANCH)
endif

# Derive from GIT if none available (local build?)
ifeq ($(BRANCH),)
BRANCH:=$(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
endif

# Default to the master branch
RELEASE:=$(firstword $(subst ., ,$(BRANCH)))
ifeq ($(RELEASE),)
RELEASE:=master
endif

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
