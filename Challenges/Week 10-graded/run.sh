#!/bin/bash

if [ -z "$1" ]
then
    echo "Error: Missing argument. Please provide the name of the Python file to run."
    exit 1
fi

counter=1
total=0

echo "Running $1 100 times..."

while [ $counter -le 100 ]
do
    echo "Iteration $counter"

    # Record start time
    start=$(date +%s.%N)

    # Run your Python program
    output=$(python3.10 "$1")
    # python3.10 "$1"


    # Check if the output contains "flag{"
    if ! echo "$output" | grep -q 'flag{' ; then
        echo "Error: Output doesn't contain 'flag{'"
        exit 1
    fi

    # Record end time
    end=$(date +%s.%N)

    # Calculate elapsed time and print it
    elapsed=$(echo "$end - $start" | bc)
    echo "Elapsed time: $elapsed seconds"

    total=$(echo "$total + $elapsed" | bc)
    # Increment counter
    counter=$((counter+1))
done

average=$(echo "scale=3; $total / 100" | bc)
echo "Average elapsed time: $average seconds"

echo "FINISHED"