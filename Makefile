all: install

exports: export CC:=${CC}
exports: export CXX:=${CXX}
exports:
	@echo "Exporting CC and CXX..."

install: | exports
	-@cmake -H. -Bbuild
	-@cmake --build build --

clean:
	-@rm -rf build
