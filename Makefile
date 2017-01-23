all:
	@printf "\n\nAvailable targets:\n"
	@printf "  devel-image - build development ready docker container\n"
	@printf "  doc-preview - Use docs image to build local preview of docs\n"
	@printf "  test-docs - Use docs image to build and test docs\n"

doc-preview:
	rm -rf docs/_build
	./scripts/docker-docs.sh make -C docs html
	@echo "To view docs:"
	@echo "open docs/_build/html/README.html"

test-docs:
	rm -rf docs/_build
	./scripts/docker-docs.sh ./scripts/test-docs.sh

devel-image:
	rm -rf _build_docker
	mkdir _build_docker
	cp requirements.txt\
	   requirements.docs.txt \
	   _build_docker/
	cp ./scripts/devel-image/Dockerfile _build_docker/
	(cd _build_docker && docker build -t f5mlb-devel .)
	rm -rf _build_docker
