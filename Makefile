all:
	@printf "\n\nAvailable targets:\n"
	@printf "  devel-image - build development ready docker container\n"
	@printf "  doc-preview - Use devel image to build local preview of docs\n"

doc-preview: doc-preview-standalone doc-preview-combined

# Build docs standalone from this repo
doc-preview-standalone:
	rm -rf docs/_build
	./scripts/run-in-docker.sh make -C docs html
	@echo "To view docs:"
	@echo "open docs/_build/html/README.html"

# Build docs from the top-level repo (github.com/f5-ci-docs)
doc-preview-combined:
	[ -d f5-ci-docs ] || git clone -b gitlab-ci git@github.com:F5Networks/f5-ci-docs.git
	./scripts/merge-docs.sh f5-ci-docs
	rm -rf f5-ci-docs/docs/_build
	./scripts/run-in-docker.sh make -C f5-ci-docs/docs html
	@echo "To view docs:"
	@echo "open f5-ci-docs/docs/_build/html/index.html"

devel-image:
	rm -rf _build_docker
	mkdir _build_docker
	cp requirements.txt\
	   requirements.docs.txt \
	   _build_docker/
	cp ./scripts/devel-image/Dockerfile _build_docker/
	(cd _build_docker && docker build -t f5mlb-devel .)
	rm -rf _build_docker
