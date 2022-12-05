BOFNAME := cEnumerateDefender

CC_x64 := x86_64-w64-mingw32-g++
CC_x86 := i686-w64-mingw32-g++

all:
	$(CC_x64) -Wno-unused-variable -Wno-write-strings -o ../dist/$(BOFNAME).x64.o -c cEnumerateDefender.cpp -masm=intel
	$(CC_x86) -Wno-unused-variable -Wno-write-strings -o ../dist/$(BOFNAME).x86.o -c cEnumerateDefender.cpp -masm=intel

debug:
	$(CC_x64) -DDEBUGBUILD -Wno-unused-variable -Wno-write-strings -o ../dist/$(BOFNAME).x64.o -c cEnumerateDefender.cpp -masm=intel
	$(CC_x86) -DDEBUGBUILD -Wno-unused-variable -Wno-write-strings -o ../dist/$(BOFNAME).x86.o -c cEnumerateDefender.cpp -masm=intel
clean:
	rm -f ../dist/$(BOFNAME).x64.o
	rm -f ../dist/$(BOFNAME).x86.o