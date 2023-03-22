#!/bin/bash

if [ -z "$1" ]
then
    echo "Error: Missing argument. Please provide the name of the Python file to run."
    exit 1
fi

counter=1
total=0

echo "Running $1 20 times..."

while [ $counter -le 20 ]
do
    echo "Iteration $counter"

    # Record start time
    start=$(date +%s.%N)

    # Run your Python program
    python3 "$1"

    # Record end time
    end=$(date +%s.%N)

    # Calculate elapsed time and print it
    elapsed=$(echo "$end - $start" | bc)
    echo "Elapsed time: $elapsed seconds"

    total=$(echo "$total + $elapsed" | bc)
    # Increment counter
    counter=$((counter+1))
done

average=$(echo "scale=3; $total / 15" | bc)
echo "Average elapsed time: $average seconds"

echo "FINISHED"