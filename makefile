# Author: Tyler Noble
	
build:  #builds executables
	gcc producer.c -o client
	gcc consumer.c -o server

c:
	gcc consumer.c -o server

p:
	gcc producer.c -o client