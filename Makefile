all: install

exports: export CXX:=${CXX}
exports:
	@echo "Exporting CXX..."

install: | exports
	-@cmake -H. -Bbuild
	-@cmake --build build --

clean:
	-@rm -rf build test/tmp
