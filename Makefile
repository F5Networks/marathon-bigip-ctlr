.PHONY: all doc-preview test-docs devel-image python-lint python-unit python-sanity

all:
	@printf "\n\nAvailable targets:\n"
	@printf "  devel-image - build development ready docker container\n"
	@printf "  doc-preview - Use docs image to build local preview of docs\n"
	@printf "  test-docs - Use docs image to build and test docs\n"

doc-preview:
	rm -rf docs/_build
	DOCKER_RUN_ARGS="-p 127.0.0.1:8000:8000" \
	  ./build-tools/docker-docs.sh make -C docs preview

test-docs:
	rm -rf docs/_build
	./build-tools/docker-docs.sh ./build-tools/test-docs.sh

devel-image:
	./build-tools/build-devel-image.sh

python-lint:
	flake8 --exclude=docs/,src/ ./
	./build-tools/lint.sh

python-unit:
	coverage run -m unittest discover -v
	coverage html
	coverage report

python-sanity: python-lint python-unit

att-gen-backends:
	docker run -v $(PWD):$(PWD) --rm -it \
		f5devcentral/attributions-generator \
		bash usr/local/bin/run-backends.sh $(PWD)

att-gen-frontend:
	docker run -v $(PWD):$(PWD) --rm -it \
		f5devcentral/attributions-generator \
		node /frontEnd/frontEnd.js $(PWD)

att-gen: att-gen-backends att-gen-frontend


