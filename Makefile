# Build commands are for GitHub CI or an explicitly authorized developer host.
.PHONY: all test clean
all test clean:
	$(MAKE) -C c $@
