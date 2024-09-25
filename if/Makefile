test-std:
	cargo test --features std
test-i686:
	cargo test --target i686-unknown-linux-gnu --no-default-features

test:
	make test-std
	make test-i686
