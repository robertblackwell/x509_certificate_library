this_file=$(realpath $0)
bin_dir=$(dirname $this_file)
project_dir=$(realpath ${bin_dir}/../)

echo this_file  : $this_file
echo bin_dir    :$bin_dir
echo project_dir: $project_dir

test=${project_dir}/cmake-build-debug/tests/test_standalone/test_standalone

valgrind --leak-check=full --leak-resolution=low --undef-value-errors=no  $test