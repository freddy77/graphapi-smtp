graphapi-smtp: main.go Makefile 
## produce static executable
	CGO_ENABLED=0 go build -tags=osusergo,netgo ./...
	strip $@
