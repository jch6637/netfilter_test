all : netfilter_test

netfilter_test : 
	gcc -o netfilter_test nfqnl_test.c -lnetfilter_queue

clean:
	rm -f netfilter_test
