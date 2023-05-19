# #!/bin/bash

# if [ -z "$1" ]
# then
#     echo "Error: Missing argument. Please provide the name of the Python file to run."
#     exit 1
# fi

# counter=1
# total=0

# echo "Running $1 50 times..."

# while [ $counter -le 50 ]
# do
#     echo "Iteration $counter"

#     # Record start time
#     start=$(date +%s.%N)

#     # Run your Python program
#     # output=$(python3.10 "$1")
#     python3.10 "$1"


#     # Check if the output contains "flag{"
#     # if ! echo "$output" | grep -q 'flag{' ; then
#     #     echo "Error: Output doesn't contain 'flag{'"
#     #     exit 1
#     # fi

#     # Record end time
#     end=$(date +%s.%N)

#     # Calculate elapsed time and print it
#     elapsed=$(echo "$end - $start" | bc)
#     echo "Elapsed time: $elapsed seconds"

#     total=$(echo "$total + $elapsed" | bc)
#     # Increment counter
#     counter=$((counter+1))
# done

# average=$(echo "scale=3; $total / 50" | bc)
# echo "Average elapsed time: $average seconds"

# echo "FINISHED"
#!/bin/bash

if [ -z "$1" ]
then
    echo "Error: Missing first argument. Please provide the name of the Python file to run."
    exit 1
fi

if [ -z "$2" ]
then
    echo "Error: Missing second argument. Please provide the number of runs to perform"
    exit 1
fi

if [ -z "$3" ]
then
    echo "Error: Missing second argument. Please provide the expected initial part for the flag, like 'hello_world' if the flag is of the time 'flag{hello_world1aq33s23rasf32tsfc}'"
    exit 1
fi

counter=1
total=0

echo "Running $1 $2 times..."

while [ $counter -le $2 ]
do
    echo "Iteration $counter"

    # Record start time
    start=$(date +%s.%N)

    # Run your Python program
    output=$(python3.10 "$1")
    # echo "$output"
    if echo "$output" | grep "flag{$3.*}"; then
        echo "Correct!"
    else
        echo "$output"
        exit
    fi


    # Record end time
    end=$(date +%s.%N)

    # Calculate elapsed time and print it
    elapsed=$(echo "$end - $start" | bc)
    echo "Elapsed time: $elapsed seconds"
    
    # Check if elapsed time is more than 270 second (4 min and 30), max runtime allowed for the lab is 5 min
    if [ ${elapsed%.*} -gt 270 ]; then
        echo "This took too long, exiting!"
        exit
    fi

    total=$(echo "$total + $elapsed" | bc)
    
    # Increment counter
    counter=$((counter+1))
done

average=$(echo "scale=3; $total / $2" | bc)
echo "Average elapsed time: $average seconds"

echo "Finished running"

