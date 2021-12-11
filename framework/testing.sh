### Testing memory leaks ###

PORTNUM = 4000

valgrind --leak-check=full --show-leak-kinds=all ./server $PORTNUM 2> /dev/null &

# Client 1
valgrind --leak-check=full --show-leak-kinds=all ./client localhost $PORTNUM 2> /dev/null &

# Client 2
./client localhost $PORTNUM 2> /dev/null &

# Client 3
./client localhost $PORTNUM 2> /dev/null &

# Client 4
./client localhost $PORTNUM 2> /dev/null &

# Client 5
./client localhost $PORTNUM 2> /dev/null &

# Client 6
./client localhost $PORTNUM 2> /dev/null &

# Client 7
./client localhost $PORTNUM 2> /dev/null &

# Client 8
./client localhost $PORTNUM 2> /dev/null &

# Client 9
./client localhost $PORTNUM 2> /dev/null &

# Client 10
./client localhost $PORTNUM 2> /dev/null &

# Client 11
./client localhost $PORTNUM 2> /dev/null &

# Client 12
./client localhost $PORTNUM 2> /dev/null &

# Client 13
./client localhost $PORTNUM 2> /dev/null &

# Client 13 (test same username! won't add)
./client localhost $PORTNUM 2> /dev/null &

# Client 14
./client localhost $PORTNUM 2> /dev/null &

# Client 15
./client localhost $PORTNUM 2> /dev/null &

# Client 16
./client localhost $PORTNUM 2> /dev/null &

# Client 17 (won't add because too many client)
./client localhost $PORTNUM 2> /dev/null &
