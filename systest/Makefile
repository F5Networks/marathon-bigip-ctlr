.PHONY: all systest functest scaletest \
	functest-setup functest-install functest-run functest-teardown \
	scaletest-setup scaletest-install scaletest-run scaletest-teardown

all:
	@printf "Available targets:\n"
	@printf "  functest - setup the functional test environment, install\n"
	@printf "      and run the functional tests, then tear down the\n"
	@printf "      functional test environment.\n"
	@printf "  functest-setup - setup the functional test environment.\n"
	@printf "  functest-install - install the system tests on the bastion\n"
	@printf "      host in the functional test environment.\n"
	@printf "  functest-run - run the system tests on the bastion host in\n"
	@printf "      the functional test environment.\n"
	@printf "  functest-teardown - tear down the functional test\n"
	@printf "      environment.\n"
	@printf "  \n"
	@printf "  scaletest - setup the scale test environment, install and\n"
	@printf "      run the scale tests, then tear down the scale test\n"
	@printf "      environment.\n"
	@printf "  scaletest-setup - setup the scale test environment.\n"
	@printf "  scaletest-install - install the system tests on the bastion\n"
	@printf "      host in the scale test environment.\n"
	@printf "  scaletest-run - run the system tests on the bastion host in\n"
	@printf "      the scale test environment.\n"
	@printf "  scaletest-teardown - tear down the scale test environment.\n"
	@printf "  \n\nRequired arguments:\n"
	@printf "  orchestration - all targets require an 'orchestration'\n"
	@printf "      value (eg. make functest-setup orchestration=k8s).\n"
	@printf "      Valid values: marathon, k8s.\n"
	@printf "  \nOptional arguments:\n"
	@printf "  bigip_ver - the version of BIG-IP to test against.\n"
	@printf "      Valid values: v12.1.0, v12.0.0, v11.6.1.\n"

VALID_ORCHESTRATIONS := marathon k8s
VALID_ORCHESTRATIONS_MSG := (valid values: marathon, k8s)

# - handle blank target and "all" separately because they do *not* require
#   the user to provide an orchestration value
ifeq ("$(MAKECMDGOALS)", "")
  $(NOOP)
else ifeq ($(MAKECMDGOALS), all)
  $(NOOP)
else
  # - validate orchestration value
  ifndef orchestration
    $(error ERROR: Orchestration value not provided $(VALID_ORCHESTRATIONS_MSG))
  else ifeq ($(orchestration), $(filter $(orchestration), $(VALID_ORCHESTRATIONS)))
    $(NOOP)
  else
    $(error ERROR: Invalid orchestration value '$(orchestration)' $(VALID_ORCHESTRATIONS_MSG))
  endif
endif

# - set testenv config file
ifeq ($(orchestration), marathon)
  repo_name := f5-marathon-lb
  testenv_config := mesos.testenv.yaml
else ifeq ($(orchestration), k8s)
  repo_name := f5-k8s-controller
  testenv_config := k8s.testenv.yaml
endif

repo := git+ssh://git@bldr-git.int.lineratesystems.com/velcro/$(repo_name).git
systest_pkg := systest_f5mlb
registry := docker-registry.pdbld.f5net.com
namespace := velcro
bigip_controller_img := $(registry)/$(namespace)/$(repo_name):master
ssh_conf := testenv_symbols/testenv_ssh_config

# - <nearest reachable tag>-<num commits since>-g<abbreviated commit id>
version := $(shell git describe --long)
export version
timestamp := $(shell date +"%Y%m%d-%H%M%S")
export timestamp
results_dir := test_results/f5mlb/f5mlb-$(version)-$(orchestration)-$(timestamp)

func_testenv_name := f5mlb_func_$(orchestration)
func_session := $(func_testenv_name)_$(version)

scale_testenv_name := f5mlb_scale_$(orchestration)
scale_session := $(scale_testenv_name)_$(version)

bigip_testenv_name := $(func_testenv_name)_bigip

# - set bigip_img for older versions, default is specified in bigip.params.yaml
bigip_current_ver := v12.1.0
bigip_oldver_1_ver := v12.0.0
bigip_oldver_1_img := bigip-osready-12.0.0.4.0.674
bigip_oldver_2_ver := v11.6.1
bigip_oldver_2_img := bigip-osready-11.6.1.1.0.326
# default to current version, will be overridden if it's put on the command line
bigip_ver := $(bigip_current_ver)
ifeq ($(bigip_ver), $(bigip_current_ver))
  bigip_params :=
else ifeq ($(bigip_ver), $(bigip_oldver_1_ver))
  bigip_params := --params $(bigip_testenv_name)/bigip_img:$(bigip_oldver_1_img)
else ifeq ($(bigip_ver), $(bigip_oldver_2_ver))
  bigip_params := --params $(bigip_testenv_name)/bigip_img:$(bigip_oldver_2_img)
else
  $(error ERROR: bigip version $(bigip_ver) is not supported)
endif


systest:
	@$(MAKE) functest
	@$(MAKE) scaletest

functest:
	@$(MAKE) functest-setup || ($(MAKE) functest-teardown && false)
	@$(MAKE) functest-install || ($(MAKE) functest-teardown && false)
	@$(MAKE) functest-run || ($(MAKE) functest-teardown && false)
	@$(MAKE) functest-teardown

scaletest:
	@$(MAKE) scaletest-setup || ($(MAKE) scaletest-teardown && false)
	@$(MAKE) scaletest-install || ($(MAKE) scaletest-teardown && false)
	@$(MAKE) scaletest-run || ($(MAKE) scaletest-teardown && false)
	@$(MAKE) scaletest-teardown

functest-install scaletest-install:
	@echo "installing $(orchestration) system tests ..."
	scp -F $(ssh_conf) \
		$(systest_pkg)/scripts/install_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion "rm -rf ~/$(systest_pkg)"
	rsync -r -e "ssh -F $(ssh_conf)" . bastion:~/$(systest_pkg)
	ssh -tF $(ssh_conf) bastion \
		"~/install_systests.sh $(repo) $(systest_pkg)"

functest-setup:
	@echo "setting up $(orchestration) functional test environment ..."
	testenv -v create --name $(func_testenv_name) \
		--config $(testenv_config) \
		--requires bigip:$(bigip_testenv_name) $(bigip_params) \
		--params num_masters:1 --params num_workers:1 \
		--vars bigip_controller_img:"$(bigip_controller_img)"

functest-run:
	@echo "running $(orchestration) functional tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh \
		$(systest_pkg) $(func_session) $(orchestration) func"

functest-teardown:
	@echo "downloading $(orchestration) functional test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(func_session)/* $(results_dir)/

	@echo "tearing down $(orchestration) functional test environment ..."
	testenv -v delete --name $(func_testenv_name) --config $(testenv_config)
	testenv -v delete --name $(bigip_testenv_name) --config bigip

scaletest-setup:
	@echo "setting up $(orchestration) scale test environment ..."
	testenv -v create --name $(scale_testenv_name) \
		--config $(testenv_config) \
		--requires bigip:$(scale_testenv_name)_bigip \
		--params bastion_flavor:m1.large \
		--params num_masters:1 --params num_workers:6 \
		--vars bigip_controller_img:"$(bigip_controller_img)"

scaletest-run:
	@echo "running $(orchestration) scale tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh \
		$(systest_pkg) $(scale_session) $(orchestration) scale"

scaletest-teardown:
	@echo "downloading $(orchestration) scale test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(scale_session)/* $(results_dir)/

	@echo "tearing down $(orchestration) scale test environment ..."
	testenv -v delete --name $(scale_testenv_name) --config $(testenv_config)
	testenv -v delete --name $(scale_testenv_name)_bigip --config bigip
