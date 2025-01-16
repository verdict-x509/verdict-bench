#!/bin/bash
# NOTE: this script is specifically written for the eval machine

set -e

# Run a command with a timer displayed on terminal
run_with_timer() {
    output_file=$1; shift

    SECONDS=0
    setsid "$@" &
    cmd_pid=$!
    pgid=$(ps -o pgid= "$cmd_pid" | tr -d ' ')

    # Function to handle cleanup on exit
    clean_up() {
        echo -e "\nterminating the child process ($cmd_pid) ..."
        kill -TERM -"${pgid}" 2>/dev/null
        wait "${cmd_pid}" 2>/dev/null
        exit 1
    }
    trap clean_up SIGINT SIGTERM

    if [ -f "$output_file" ]; then
        init_processed="$(wc -l < $output_file)"
    else
        init_processed=0
    fi

    while kill -0 $cmd_pid 2>/dev/null; do
        total_ct_logs=10627993
        if [ -f "$output_file" ]; then
            processed="$(wc -l < $output_file)"
            if [ "$((processed - init_processed))" -ne 0 ]; then
                eta_seconds="$(echo "scale=4; ($total_ct_logs - $processed) / ($processed - $init_processed) * $SECONDS" | bc)"
                eta_seconds="$(printf %.0f "$eta_seconds")"
                printf "\033[2K\rprocessed: %d (%.2f%%), elapsed: %02d:%02d:%02d, eta: %02d:%02d:%02d" \
                    $processed \
                    "$(echo "scale=4; $processed / $total_ct_logs * 100" | bc)" \
                    $((SECONDS / 3600)) $(((SECONDS / 60) % 60)) $((SECONDS % 60)) \
                    $((eta_seconds / 3600)) $(((eta_seconds / 60) % 60)) $((eta_seconds % 60))
            else
                # Wait until it outputs to record the time
                SECONDS=0
            fi
        fi
        sleep 1
    done
    wait $cmd_pid
    echo

    trap - SIGINT SIGTERM
}

make reduce-noise ISOLATE_CORES=2,4,6,8 CORE_FREQUENCY=2401000

harnesses=(
    verdict-chrome verdict-firefox verdict-openssl
	verdict-chrome-aws-lc chrome verdict-firefox-aws-lc verdict-openssl-aws-lc
	chrome firefox openssl
	hammurabi-chrome hammurabi-firefox armor ceres
)

for harness in "${harnesses[@]}"; do
    echo "### benchmarking $harness ###"

    # Restore progress
    if [ -f bench-results/$harness.txt ]; then
        processed="$(wc -l < bench-results/$harness.txt)"
        BENCH_FLAGS="--skip $processed"
        echo "restoring progress of $processed certificates"
    else
        BENCH_FLAGS=
    fi

    run_with_timer bench-results/$harness.txt \
        make bench-$harness \
            BENCH_FLAGS="$BENCH_FLAGS" \
            CT_LOG=~/work/mega-crl \
            CT_LOG_TESTS="$(ls ~/work/mega-crl/certs/cert-list-*.txt | sort | xargs)" \
            ISOLATE_CORES=2,4,6,8 \
            BENCH_OUTPUT=">> bench-results/$harness.txt"
done
