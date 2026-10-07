test-std:
	RUST_TEST_THREADS=1 cargo test --features std
test-i686:
	RUST_TEST_THREADS=1 cargo test --target i686-unknown-linux-gnu --no-default-features

test:
	make test-std
	make test-i686
