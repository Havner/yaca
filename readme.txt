YACA - Yet Another Crypto API

Basic information:

Code Style (for now):
	Tabs (8-chars) + spaces;
	$ astyle -T8 <file>

Project structure:
	api/ - Public API (headers)

	demos/ - Demo applications
	doc/ - Documentation
	examples/ - Usage examples

	src/ - source

	test/ - tests

General design:
	- All memory allocated by API should be freed with yaca_free()
	- Contexts and keys should be freed with yaca_ctx_free()/yaca_key_free()
	- Function names: yaca_<operation/object>_<function>; Ex: yaca_verify_init()
	- Simplified/Simple functions don't have <operation/object> part
	- Enums: YACA_<concept>_<value>; Ex: YACA_KEY_256BIT
	- Objects (context, key) end with _h
	- Most functions return 0 on success, negative values on error

Simplified API:
	- Is located in simple.h
	- Currently, to use it - some functions from crypto.h and key.h are needed
	- Symmetric ciphers (except for GCM) and message digests are only operations that are supported
	- All operations are single-shot and output is allocated by library

API:
	1) All contexts are created by appropriate init() functions
	2) Keys are created by generate or import functions

Examples:
	- It is possible to compile-check examples with "make" command
