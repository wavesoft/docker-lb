VERSION := $(shell git rev-parse --short HEAD)
IMAGE_NAME = "wavesoft/docker-lb"

.PHONY: docker push

docker:
	docker build \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):latest \
		.

push:
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest
