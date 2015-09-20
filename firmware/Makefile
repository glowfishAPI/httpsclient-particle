# Recursively build the directories below
# 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
all:
	$(MAKE) --directory=core
	$(MAKE) --directory=crypto
	$(MAKE) --directory=matrixssl

test:
	$(MAKE) --directory=crypto/test
	$(MAKE) --directory=matrixssl/test
	if [ -d "./apps" ];then $(MAKE) --directory=apps; fi

clean:
	$(MAKE) clean --directory=core
	$(MAKE) clean --directory=crypto
	$(MAKE) clean --directory=crypto/test
	$(MAKE) clean --directory=matrixssl
	$(MAKE) clean --directory=matrixssl/test
	if [ -d "./apps" ];then $(MAKE) clean --directory=apps; fi

