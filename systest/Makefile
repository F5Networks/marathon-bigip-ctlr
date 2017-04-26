.PHONY: all systest functest scaletest hatest smoketest symlink_symbols \
	functest-setup functest-install functest-run functest-teardown \
	scaletest-setup scaletest-install scaletest-run scaletest-teardown \
	hatest-setup hatest-install hatest-run hatest-teardown \
	smoketest-setup smoketest-install smoketest-run smoketest-teardown

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
	@printf "      environment.\n\n"
	@printf "  scaletest - setup the scale test environment, install and\n"
	@printf "      run the scale tests, then tear down the scale test\n"
	@printf "      environment.\n"
	@printf "  scaletest-setup - setup the scale test environment.\n"
	@printf "  scaletest-install - install the system tests on the bastion\n"
	@printf "      host in the scale test environment.\n"
	@printf "  scaletest-run - run the system tests on the bastion host in\n"
	@printf "      the scale test environment.\n"
	@printf "  scaletest-teardown - tear down the scale test environment.\n\n"
	@printf "  hatest - setup the BigIP HA test environment, install and\n"
	@printf "      run the BigIP HA tests, then tear down the scale test\n"
	@printf "      environment.\n"
	@printf "  hatest-setup - setup the BigIP HA test environment.\n"
	@printf "  hatest-install - install the system tests on the bastion\n"
	@printf "      host in the BigIP HA test environment.\n"
	@printf "  hatest-run - run the BigIP HA tests on the bastion host in\n"
	@printf "      the BigIP HA test environment.\n"
	@printf "  hatest-teardown - tear down the BigIP HA test environment.\n\n"
	@printf "  smoketest - setup the smoke test environment, install\n"
	@printf "      and run the smoke tests, then tear down the\n"
	@printf "      smoke test environment.\n"
	@printf "  smoketest-setup - setup the smoke test environment.\n"
	@printf "  smoketest-install - install the system tests on the bastion\n"
	@printf "      host in the smoke test environment.\n"
	@printf "  smoketest-run - run the system tests on the bastion host in\n"
	@printf "      the smoke test environment.\n"
	@printf "  smoketest-teardown - tear down the smoke test\n"
	@printf "      environment.\n"
	@printf "  \n\nRequired arguments:\n"
	@printf "  orchestration - all targets require an 'orchestration'\n"
	@printf "      value (eg. make functest-setup orchestration=k8s).\n"
	@printf "      Valid values: marathon, k8s.\n"
	@printf "  \nOptional arguments:\n"
	@printf "  bigip_ver - the version of BIG-IP to test against.\n"
	@printf "      Valid values: v12.1.0, v12.0.0, v11.6.1.\n"
	@printf "      Default is v12.1.0 if not specified. If specified\n"
	@printf "      the resulting BIG-IP name includes version & stack name.\n"
	@printf "  bigip_pool_mode - pool member mode to use for the tests\n"
	@printf "      Valid values: nodeport cluster.\n"

VALID_ORCHESTRATIONS := marathon k8s openshift
VALID_ORCHESTRATIONS_MSG := (valid values: marathon, k8s, openshift)

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

# - set testenv config file (mesos.testenv.yaml for stand-alone mesos marathon)
ifeq ($(orchestration), marathon)
  repo_name := marathon-bigip-ctlr
  testenv_config := dcos.testenv.yaml
  project_dir := velcro.marathon-bigip-ctlr
  bigip_pool_mode ?= cluster
  testenv_stack_timeout := 600
else ifeq ($(orchestration), k8s)
  repo_name := k8s-bigip-ctlr
  testenv_config := k8s.testenv.yaml
  project_dir := velcro.k8s-bigip-ctlr
  bigip_pool_mode ?= nodeport
  testenv_stack_timeout := 600
else ifeq ($(orchestration), openshift)
  repo_name := k8s-bigip-ctlr
  testenv_config := openshift.testenv.yaml
  project_dir := velcro.openshift-bigip-ctlr
  bigip_pool_mode ?= cluster
  testenv_stack_timeout := 1800
endif

# - <nearest reachable tag>-<num commits since>-g<abbreviated commit id>
version := $(shell git describe --long)
export version
timestamp := $(shell date +"%Y%m%d-%H%M%S")
export timestamp

# - set testenv name
ifeq ($(findstring functest, $(MAKECMDGOALS)), functest)
  testenv_name := f5mlb_func_$(orchestration)
else ifeq ($(findstring scaletest, $(MAKECMDGOALS)), scaletest)
  testenv_name := f5mlb_scale_$(orchestration)
else ifeq ($(findstring hatest, $(MAKECMDGOALS)), hatest)
  testenv_name := f5mlb_ha_$(orchestration)
else ifeq ($(findstring smoketest, $(MAKECMDGOALS)), smoketest)
  testenv_name := f5mlb_smoke_$(orchestration)
else
  $(error ERROR: failed to calc testenv name.)
endif
session := $(testenv_name)_$(version)
symbols_dir := $(CURDIR)/$(testenv_name)
bigip_testenv_name := $(testenv_name)_bigip

repo := git+ssh://git@gitlab.pdbld.f5net.com/$(namespace)/$(repo_name).git
systest_pkg := systest_f5mlb
registry := docker-registry.pdbld.f5net.com
namespace := velcro
bigip_controller_img := $(registry)/$(namespace)/$(repo_name):master
ssh_conf := $(symbols_dir)/testenv_ssh_config
results_dir := test_results/$(project_dir)/f5mlb-$(version)-$(orchestration)-$(timestamp)

# - set bigip_img for older versions, default is specified in bigip.params.yaml
bigip_current_ver := v12.1.0
bigip_oldver_1_ver := v12.0.0
bigip_oldver_1_img := bigip-osready-12.0.0.4.0.674
bigip_oldver_2_ver := v11.6.1
bigip_oldver_2_img := bigip-osready-11.6.1.1.0.326

ifeq ($(bigip_ver), )
  bigip_params :=
else ifeq ($(bigip_ver), v12.1.0)
  bigip_params :=
else ifeq ($(bigip_ver), $(bigip_oldver_1_ver))
  bigip_params := --params $(bigip_testenv_name)/bigip_img:$(bigip_oldver_1_img)
else ifeq ($(bigip_ver), $(bigip_oldver_2_ver))
  bigip_params := --params $(bigip_testenv_name)/bigip_img:$(bigip_oldver_2_img)
else
  $(error ERROR: bigip version $(bigip_ver) is not supported)
endif

# function call to name specific version of bigip
named_bigip = bigip:$(1)_bigip_$(bigip_ver)

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

hatest:
	@$(MAKE) hatest-setup || ($(MAKE) hatest-teardown && false)
	@$(MAKE) hatest-install || ($(MAKE) hatest-teardown && false)
	@$(MAKE) hatest-run || ($(MAKE) hatest-teardown && false)
	@$(MAKE) hatest-teardown

smoketest:
	@$(MAKE) smoketest-setup || ($(MAKE) smoketest-teardown && false)
	@$(MAKE) smoketest-install || ($(MAKE) smoketest-teardown && false)
	@$(MAKE) smoketest-run || ($(MAKE) smoketest-teardown && false)
	@$(MAKE) smoketest-teardown

symlink_symbols:
	if [ -d testenv_symbols ]; then rm -rf testenv_symbols; fi
	if [ -L testenv_symbols ]; then rm testenv_symbols; fi
	ln -s $(testenv_name) testenv_symbols

functest-install scaletest-install hatest-install smoketest-install:
	@echo "installing $(orchestration) system tests ..."
	scp -F $(ssh_conf) \
		$(systest_pkg)/scripts/install_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion "rm -rf ~/$(systest_pkg)"
	rsync -r -e "ssh -F $(ssh_conf)" . bastion:~/$(systest_pkg)
	ssh -tF $(ssh_conf) bastion \
		"~/install_systests.sh $(repo) $(systest_pkg)"

functest-setup: symlink_symbols
	@echo "setting up $(orchestration) functional test environment ..."
	@echo "BIG-IP under test: $(bigip_current_ver)"
	TESTENV_STACK_TIMEOUT=$(testenv_stack_timeout) \
		testenv -v create --name $(testenv_name) \
		--output-dir $(symbols_dir) \
		--requires $(if $(bigip_ver), $(call named_bigip,$(testenv_name)),bigip) $(bigip_params) \
		--params num_masters:1 --params num_workers:2 \
		--vars bigip_controller_img:"$(bigip_controller_img)" \
		$(testenv_config)

functest-run:
	@echo "running $(orchestration) functional tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh \
		$(systest_pkg) $(session) $(orchestration) func $(bigip_pool_mode)"

functest-teardown:
	@echo "downloading $(orchestration) functional test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(session)/* $(results_dir)/

	@echo "tearing down $(orchestration) functional test environment ..."
	testenv delete --name $(testenv_name) $(testenv_config)

scaletest-setup: symlink_symbols
	@echo "setting up $(orchestration) scale test environment ..."
	@echo "BIG-IP under test: $(bigip_current_ver)"
	TESTENV_STACK_TIMEOUT=$(testenv_stack_timeout) \
		testenv -v create --name $(testenv_name) \
		--output-dir $(symbols_dir) \
		--requires $(if $(bigip_ver), $(call named_bigip,$(testenv_name)),bigip) $(bigip_params) \
		--params bastion_flavor:m1.large \
		--params num_masters:1 --params num_workers:6 \
		--vars bigip_controller_img:"$(bigip_controller_img)" \
		$(testenv_config)

scaletest-run:
	@echo "running $(orchestration) scale tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh \
		$(systest_pkg) $(session) $(orchestration) scale $(bigip_pool_mode)"

scaletest-teardown:
	@echo "downloading $(orchestration) scale test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(session)/* $(results_dir)/

	@echo "tearing down $(orchestration) scale test environment ..."
	testenv delete --name $(testenv_name) $(testenv_config)

hatest-setup: symlink_symbols
	@echo "setting up $(orchestration) HA test environment ..."
	@echo "BIG-IP under test: $(bigip_current_ver)"
	TESTENV_STACK_TIMEOUT=$(testenv_stack_timeout) \
		testenv -v create --name $(testenv_name) \
		--output-dir $(symbols_dir) \
		--requires bigip1-ha:$(testenv_name)_bigip1 \
		--requires bigip2-ha:$(testenv_name)_bigip2 \
		--params num_masters:1 --params num_workers:1 \
		--vars bigip_controller_img:"$(bigip_controller_img)" \
		$(testenv_config)

hatest-run:
	@echo "running $(orchestration) HA tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"export OS_TENANT_ID=$(OS_TENANT_ID) &&" \
		"export OS_PROJECT_NAME=$(OS_PROJECT_NAME) &&" \
		"export OS_USERNAME=$(OS_USERNAME) &&" \
		"export OS_PASSWORD=$(OS_PASSWORD) &&" \
		"export OS_AUTH_URL=$(OS_AUTH_URL) &&" \
		"~/run_systests.sh \
		$(systest_pkg) $(session) $(orchestration) ha $(bigip_pool_mode)"

hatest-teardown:
	@echo "downloading $(orchestration) HA test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(session)/* $(results_dir)/

	@echo "tearing down $(orchestration) HA test environment ..."
	testenv delete --name $(testenv_name) $(testenv_config)
	testenv delete --name $(testenv_name)_bigip1 bigip1-ha
	testenv delete --name $(testenv_name)_bigip2 bigip2-ha

smoketest-setup: symlink_symbols
	@echo "setting up $(orchestration) smoke test environment ..."
	@echo "BIG-IP under test: $(bigip_current_ver)"
	TESTENV_STACK_TIMEOUT=$(testenv_stack_timeout) \
		testenv -v create --name $(testenv_name) \
		--output-dir $(symbols_dir) \
		--requires $(if $(bigip_ver), $(call named_bigip,$(testenv_name)),bigip) $(bigip_params) \
		--params num_masters:1 --params num_workers:2 \
		--vars bigip_controller_img:"$(bigip_controller_img)" \
		$(testenv_config)

smoketest-run:
	@echo "running $(orchestration) smoke tests ..."
	scp -F $(ssh_conf) $(systest_pkg)/scripts/run_systests.sh bastion:~/
	ssh -tF $(ssh_conf) bastion \
		"~/run_systests.sh \
		$(systest_pkg) $(session) $(orchestration) smoke $(bigip_pool_mode)"

smoketest-teardown:
	@echo "downloading $(orchestration) smoke test results ..."
	if [ ! -e $(results_dir) ]; then mkdir -p $(results_dir); fi
	-scp -rp -F $(ssh_conf) \
		bastion:~/test_results/$(session)/* $(results_dir)/

	@echo "tearing down $(orchestration) smoke test environment ..."
	testenv delete --name $(testenv_name) $(testenv_config)
