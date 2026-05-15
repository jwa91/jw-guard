.PHONY: build install check test clean

build:
	cargo build --workspace

install:
	cargo install --path cli

check:
	cargo check --workspace --all-targets
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

clean:
	cargo clean
