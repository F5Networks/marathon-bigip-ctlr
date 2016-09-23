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

VALID_ORCHESTRATIONS := marathon k8s
export VALID_ORCHESTRATIONS
VALID_ORCHESTRATIONS_MSG := (valid values: marathon, k8s)
export VALID_ORCHESTRATIONS_MSG

define ORCHESTRATION_PROMPT
Enter orchestration system $(VALID_ORCHESTRATIONS_MSG):  
endef

ifeq ("$(MAKECMDGOALS)", "")
  $(NOOP)
else ifeq ($(MAKECMDGOALS), all)
  $(NOOP)
else
  # - prompt for orchestration value if not provided
  ifndef orchestration
    orchestration := $(shell bash -c 'read -p "$(ORCHESTRATION_PROMPT)" val; echo $$val')
    export orchestration
  endif

  # - validate orchestration value
  ifndef orchestration
    $(error ERROR: Orchestration value not provided $(VALID_ORCHESTRATIONS_MSG))
  else ifeq ($(orchestration), $(filter $(orchestration), $(VALID_ORCHESTRATIONS)))
    @echo "orchestration system = $(orchestration)"
  else
    $(error ERROR: Invalid orchestration value '$(orchestration)' $(VALID_ORCHESTRATIONS_MSG))
  endif
endif

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
results_dir := test_results/f5mlb/f5mlb-$(version)-$(orchestration)-$(timestamp)

func_testenv_name := f5mlb_func_$(orchestration)
func_session := $(func_testenv_name)_$(version)

scale_testenv_name := f5mlb_scale_$(orchestration)
scale_session := $(scale_testenv_name)_$(version)


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
		--vars f5mlb_img:"$(f5mlb_img)"

functest-run:
	@echo "running functional tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh \
		$(systest_pkg) $(func_session) func $(orchestration)"

functest-teardown:
	@echo "downloading functional test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(func_session)/* $(results_dir)/

	@echo "tearing down functional test environment ..."
	testenv delete --name $(func_testenv_name)

scaletest-setup:
	@echo "setting up scale test environment ..."
	testenv create --name $(scale_testenv_name) \
		--config mesos.testenv.yaml \
		--requires bigip \
		--params num_masters:1 num_workers:6 \
		--vars f5mlb_img:"$(f5mlb_img)"

scaletest-run:
	@echo "running scale tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh \
		$(systest_pkg) $(scale_session) scale $(orchestration)"

scaletest-teardown:
	@echo "downloading scale test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(scale_session)/* $(results_dir)/

	@echo "tearing down scale test environment ..."
	testenv delete --name $(scale_testenv_name)
