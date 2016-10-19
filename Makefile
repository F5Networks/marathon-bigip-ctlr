all:
	@printf "\n\nAvailable targets:\n"
	@printf "  devel-image - build development ready docker container\n"

devel-image:
	docker build -t f5mlb-devel -f ./scripts/devel-image/Dockerfile .
