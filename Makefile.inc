PROG=easyseed
MANSEC=1
OBJS=	$(PROG).o \
	vectors.o

WORDLISTS=	chinese_simplified \
		chinese_traditional \
		english \
		french \
		italian \
		japanese \
		korean \
		spanish

#manfmt: $(PROG).$(MANSEC).html $(PROG).$(MANSEC).md $(PROG).$(MANSEC).txt
manfmt: $(PROG).$(MANSEC).html $(PROG).$(MANSEC).txt

$(PROG).$(MANSEC).html: $(PROG).$(MANSEC)
	mandoc -I os=Bitcoin -T html $< > $@

#Currently broken with message:
#mandoc -I os=Bitcoin -T markdown easyseed.1 > easyseed.1.md
#mandoc: mdoc_markdown.c:333: md_node: Assertion `n->tok >= MDOC_Dd && n->tok < MDOC_MAX' failed.
#$(PROG).$(MANSEC).md: $(PROG).$(MANSEC)
#	mandoc -I os=Bitcoin -T markdown $< > $@

$(PROG).$(MANSEC).txt: $(PROG).$(MANSEC)
	# XXX: Ridiculous kludge around make/shell quoting issues which
	# prevent me from simply using sed expression $'s/[^\b]\b//g' :
	mandoc -I os=Bitcoin -T utf8 $< | \
		tr '\b' '^' | sed $(SEDRE) -e 's/[^^]\^//g' > $@

wordlist.h: wordlist/*
	for lang in $(WORDLISTS) ; do \
		echo "const char *$${lang}[2048] = {" ; \
		{ \
			ctr=2048 ; \
			while read w ; do \
				if [ $$((ctr -= 1)) -eq 0 ] ; then \
					printf '\tu8"%s"\n};\n' "$$w" ; \
				else \
					printf '\tu8"%s",\n' "$$w" ; \
				fi ; \
			done < wordlist/$${lang}.txt ; \
		} ; \
	done > $@

clean:
	rm -f $(PROG) $(OBJS) wordlist.h \
		$(PROG).$(MANSEC).html $(PROG).$(MANSEC).md $(PROG).$(MANSEC).txt

check: $(PROG)
	./$(PROG) -T
