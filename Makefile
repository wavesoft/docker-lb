VERSION := $(shell git describe --tags)
IMAGE_NAME = "wavesoft/docker-lb"

.PHONY: build

build:
	docker build \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):latest \
		.
