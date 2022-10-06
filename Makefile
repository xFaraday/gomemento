all: init generate

init:
	@echo "Making gomemento..."
#add special compiler options beyond -w later,
#maybe use a packer or some sort.
generate:
	go build -ldflags "-w" .

clean:
	@echo "done."
