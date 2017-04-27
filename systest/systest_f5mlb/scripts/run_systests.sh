#!/usr/bin/env bash
set -ex

if [ "$1" == "" ]; then
    echo "ERROR: no systest_pkg value provided!"
    exit 1
else
    systest_pkg="$1"
fi

if [ "$2" == "" ]; then
    echo "ERROR: no session value provided!"
    exit 1
else
    session="$2"
fi

if [ "$3" == "" ]; then
    echo "ERROR: no orchestration value provided!"
    exit 1
else
    orchestration="$3"
fi

if [ "$4" == "" ]; then
    echo "ERROR: no include_tags value provided!"
    exit 1
else
    # - include tags is a (potentially space-delimited) value like "func",
    #   "scale" or "func perf"
    include_tags="$4"
fi

if [ "$5" == "" ]; then
    echo "ERROR: no pool_mode value provided!"
    exit 1
else
    # - pool_mode is pytest variable that runs the tests with the controller in
    # with the specified pool_member_typw
    #   "nodeport" or "cluster"
    pool_mode="$5"
fi

# - create the local results directory
results_dir=~/test_results
if [[ ! -e $results_dir ]]; then
    mkdir -p $results_dir"
fi

# - enter the systest virtualenv
source systest/bin/activate

# - run the system tests
systestdir=$(python -c "import $systest_pkg; print $systest_pkg.__path__[0]")
cd $systestdir

py.test \
    -svvra \
    --symbols ~/testenv_symbols/testenv_symbols.json \
    --vars controller-pool-mode:$pool_mode \
    --include $include_tags \
    --exclude incomplete no_regression no_$orchestration no_pool_mode_$pool_mode \
    --autolog-outputdir $results_dir \
    --autolog-session $session \
    -- testsuites \
&& rc=$? || rc=$?

# - pytest return codes:
#   - 0 => tests ran and passed
#   - 1 => tests ran and failed
#   - 2 => pytest error (eg. invalid command line argument)
#   - 3 => tests ran with errors (ie. threw exceptions)
#   - 4 => invalid test path (ie. file not found)
#   - 5 => no tests collected/run
if (( $rc == 1 )); then
    exit 0
else
    exit $rc
fi
