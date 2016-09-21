.PHONY: all systest functest scaletest \
	functest-setup functest-install functest-run functest-teardown \
	scaletest-setup scaletest-install scaletest-run scaletest-teardown

repo := git+ssh://git@bldr-git.int.lineratesystems.com/velcro/f5-marathon-lb.git
systest_pkg := systest_f5mlb
registry := docker-registry.pdbld.f5net.com
namespace := velcro
f5mlb_img := $(registry)/$(namespace)/f5-marathon-lb:master
ssh_conf := testenv_symbols/testenv_ssh_config

# - <nearest reachable tag>-<num commits since>-g<abbreviated commit id>
version := $(shell git describe --long)
export version
timestamp := $(shell date +"%Y%m%d-%H%M%S")
export timestamp
results_dir := test_results/f5mlb/f5mlb-$(version)-$(timestamp)

func_testenv_name := f5mlb_func
func_session := $(func_testenv_name)_$(version)

scale_testenv_name := f5mlb_scale
scale_session := $(scale_testenv_name)_$(version)


all: systest

systest: functest scaletest

functest: functest-setup functest-install functest-run functest-teardown

scaletest: scaletest-setup scaletest-install scaletest-run scaletest-teardown

functest-install scaletest-install:
	@echo "installing system tests ..."
	scp -F $(ssh_conf) \
		$(systest_pkg)/scripts/install_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/install_systests.sh $(repo) $(systest_pkg)"

functest-setup:
	@echo "setting up functional test environment ..."
	testenv create --name $(func_testenv_name) \
		--config mesos.testenv.yaml \
		--requires bigip \
		--params num_masters:1 num_workers:1 \
		--vars f5mlb_img:"$(f5mlb_img)" \
		|| true

functest-run:
	@echo "running functional tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh $(systest_pkg) $(func_session) func" \
		|| true

functest-teardown:
	@echo "downloading functional test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(func_session)/* $(results_dir)/ \
		|| true

	@echo "tearing down functional test environment ..."
	testenv delete --name $(func_testenv_name) || true

scaletest-setup:
	@echo "setting up scale test environment ..."
	testenv create --name $(scale_testenv_name) \
		--config mesos.testenv.yaml \
		--requires bigip \
		--params num_masters:1 num_workers:6 \
		--vars f5mlb_img:"$(f5mlb_img)" \
		|| true

scaletest-run:
	@echo "running scale tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh $(systest_pkg) $(scale_session) scale" \
		|| true

scaletest-teardown:
	@echo "downloading scale test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(scale_session)/* $(results_dir)/ \
		|| true

	@echo "tearing down scale test environment ..."
	testenv delete --name $(scale_testenv_name) || true
