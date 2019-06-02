all: pam-module tests

pam-module:
	g++ -g -std=c++17 -fPIC -c last-resort.cpp common-raii/common-raii.cpp -Wl,--no-undefined
	g++ -g -std=c++17 -shared -o last-resort.so last-resort.o common-raii.o -Wl,--no-undefined -lpam `gpgme-config --cflags --libs` -lmicrohttpd -lstdc++fs

tests: pam-module
	g++ -g pam-tests.cpp common-raii/common-raii.cpp -Wl,--no-undefined -o pam-tests -std=c++17 -lgtest -lgmock -lpthread -lpam `gpgme-config --cflags --libs`  -lmicrohttpd -lstdc++fs 
run-unit-tests: tests
	LD_PRELOAD=libpam_wrapper.so PAM_WRAPPER=1 PAM_WRAPPER_SERVICE_DIR=./config/ ./pam-tests
clean:
	rm *.so *.o pam-tests
