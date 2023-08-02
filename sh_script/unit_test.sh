readonly script_name=${0##*/}

unit_test_folder=(
    "src/protocol"
)

export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="unittest-%p-%m.profraw"

find . -name "*.profraw" | xargs rm -rf

for path in ${unit_test_folder[@]}; do
    pushd $path
    cargo test
    grcov . --binary-path ../../target/debug/ -s . -t html --branch --ignore-not-existing -o unit_test_coverage
    popd
done

unset RUSTFLAGS
unset LLVM_PROFILE_FILE