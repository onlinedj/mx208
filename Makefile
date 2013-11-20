#makefile for building multi target

objects_c = client.o
client: $(objects_c)
	gcc -o client $(objects_c)

objects_s = mxserver.o connection_handler.o queue.o command_handler.o
mxserver: $(objects_s)
	gcc -o mxserver $(objects_s) -lpthread 

.PHONY: clean
clean: 
	-rm mxserver $(objects_s) client $(objects_c)
