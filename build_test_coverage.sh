#!/bin/bash

if [ ! -f api/yaca/yaca_crypto.h ]; then
	echo "Run this script from root of the YACA repository"
	exit 1
fi

if ! gcov --version > /dev/null; then
	echo "You need to install gcov tool"
	exit 1
fi

rm -rf build/coverage || exit 1
mkdir -p build/coverage || exit 1

find . -name "*.gcda" -print0 | xargs -0 rm -f

cmake -H. -Bbuild -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Coverage || exit 1
cmake --build build -- -j8 || exit 1

pushd build/tests
./yaca-unit-tests || exit 1
lcov --capture --directory "CMakeFiles/yaca-unit-tests.dir" --output-file "yaca.info" || exit 1
lcov --remove "yaca.info" "/usr/include/*" "/usr/lib/*" -o "yaca_f.cov"
genhtml "yaca_f.cov" --output-directory ../coverage
popd

echo
echo "You can open the build/coverage/index.html file now in your browser."
echo
