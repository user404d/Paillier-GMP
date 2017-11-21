all: install

exports: export CXX:=${CXX}
exports:
	@echo "Exporting CXX..."

dirs:
	@test -d bin || mkdir bin
	@test -d lib || mkdir lib
	@test -d test/tmp || mkdir test/tmp

install: | exports dirs
	@if [[ -z `which ninja` ]]; then cmake -H. -Bbuild; else cmake -G Ninja -H. -Bbuild; fi
	@cmake --build build --
	@test -d build/tmp || mkdir build/tmp

clean:
	-@rm -rf build test/tmp
