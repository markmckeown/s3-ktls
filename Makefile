S3_KTLS_SRC = s3-ktls.c 
S3_KTLS_EXE = s3-ktls
LIBS   = -lssl -lcrypto -luring
CFLAGS = -O2 -Wall -Wextra -Werror

.PHONY: all
all: $(S3_KTLS_EXE)


.PHONY: clean
clean:
	rm -f $(S3_KTLS_EXE)

$(S3_KTLS_EXE): $(S3_KTLS_SRC)
	gcc $(CFLAGS) $(S3_KTLS_SRC) -o $(S3_KTLS_EXE) $(LIBS)

