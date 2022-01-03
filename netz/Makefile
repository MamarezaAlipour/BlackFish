all:
	@sh ./configure CREATE_VERSION_H
	@make -f Makefile.tmp
	@rm Makefile.tmp

depend:
	@sh ./configure CREATE_VERSION_H
	@make -f Makefile.tmp depend 
	@rm Makefile.tmp

clean:
	@sh ./configure
	@make -f Makefile.tmp clean
	@rm Makefile.tmp

install:
	@sh ./configure
	@make -f Makefile.tmp install
	@rm Makefile.tmp

uninstall:
	@sh ./configure
	@make -f Makefile.tmp uninstall
	@rm Makefile.tmp

