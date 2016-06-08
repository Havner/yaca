YACA - Yet Another Crypto API

Basic information:

Code Style:
	Tizen coding style (doc/coding-rules.txt)

Project structure:
	api/yaca/  - Public API (headers)
	doc/       - Documentation
	examples/  - Usage examples
	packaging/ - RPM spec file
	src/       - Source

General design:
	- All memory allocated by API should be freed with yaca_free()
	- Contexts and keys should be freed with yaca_context_destroy()/yaca_key_destroy()
	- Function names: yaca_<operation/object>_<function>; Ex: yaca_verify_initialize()
	- Simplified/Simple functions don't have <operation/object> part, but have <simple> prefix
	- Enums: YACA_<concept>_<value>; Ex: YACA_KEY_LENGTH_256BIT
	- Objects (context, key) end with _h
	- Functions returns YACA_ERROR_NONE on success, negative values on error

Simplified API:
	- Is located in yaca_simple.h
	- Currently, to use it - some functions from yaca_crypto.h and yaca_key.h are needed
	- Symmetric ciphers (except for GCM and CCM),
          message digests and signatures are only operations that are supported
	- All operations are single-shot and output is allocated by library

API:
	- All contexts are created by appropriate _initialize() functions
	- Keys are created by generate or import functions

Examples:
	- It is possible to compile-check examples with "make" command

Tests:
	All tests are developed at security-tests repository from tizen.org, branch yaca.
	git clone ssh://[USER_ID]@review.tizen.org:29418/platform/core/test/security-tests -b yaca
	Build all tests with command: cmake -DBUILD_ALL_TESTS=OFF -DBUILD_YACA=ON; make
	Run all tests with command: yaca-test
