release:
	make -f Makefile.loader
	mv EBOOT.prx EBOOT.BIN
debug: 
	make -f Makefile.loader DEBUG=1
	mv EBOOT.prx EBOOT.BIN
clean: 
	make -f Makefile.loader clean
	rm EBOOT.BIN
cmake:
	cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$PSPDEV/psp/share/pspdev.cmake -B build .