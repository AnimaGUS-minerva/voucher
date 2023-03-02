build-std:
	cargo build --lib --release --features std
build-i686:
	cargo build --lib --release --target i686-unknown-linux-gnu --no-default-features
test-std:
	cargo test --features std
test-i686:
	cargo test --target i686-unknown-linux-gnu --no-default-features

test:
	make build-std
	make build-i686
	make test-std
	make test-i686
