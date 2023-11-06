.PHONY: all docker

all: docker
docker:
	docker build --platform=linux/amd64 -t server .
