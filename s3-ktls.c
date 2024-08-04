/**
 * Copyright (C) Cirata 2024 mark.mckeown@cirata.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <sys/sendfile.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <liburing.h>
#include <poll.h>

#define DIGEST_SIZE      128
#define FOUR_K           4096
#define SIXTEEN_K        16384
#define DATE_BUFFER_SIZE 128

/**
 * Test uploading a file to S3 using Kernel TLS
 *
 * Load TLS module
 *
 * sudo modprobe tls
 *
 * mmk@ubuntu-build:~/s3-ktls$ lsb_release -a
 * No LSB modules are available.
 * Distributor ID:	Ubuntu
 * Description:	Ubuntu 22.04.1 LTS
 * Release:	22.04
 * Codename:	jammy
 * 
 * mmk@ubuntu-build:~/s3-ktls$ openssl version
 * OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
 * mmk@ubuntu-build:~/s3-ktls$ lsmod | grep tls
 * tls                   114688  0
 *
 *
 * If SSL connection can use Kernel TLS then
 * sendfile is used, otherwise normal
 * copy happens. Sample usage:
 *
 * s3-ktls --file s3-ktls.c  --bucket mmk-s3-test-multi-part-upload --region us-east-2
 *
 * Significant functionality is implementing AWS V4 Signature,
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 */

/**
 * State of the execution.
 */
struct config {
	// File information: name, size and fd.
	char *file;
	off_t file_size;
	int file_fd;

	// S3 configuration.
	char *bucket;
	char *region;
	
	// HTTP Headers
	char *path;
	char *hostname;
	char *http_date;
	char *auth_header;
	char *http_header;

	// AWS v4 Signing state. 
	unsigned char signing_key[EVP_MAX_MD_SIZE];
	uint32_t signing_key_size;
	char *aws_access_key_id;	// AWS_ACCESS_KEY_ID
	char *aws_secret_access_key;	// AWS_SECRET_ACCESS_KEY
	char *aws_session_token;	// AWS_SESSION_TOKEN
	char *aws_day_date;
	char *aws_date_time;
	char *urlencoded_path;

	// AWS connection state.
	SSL_CTX *ssl_ctx;
	SSL *ssl;           // SSL wrapper for connection.
	bool ssl_debug;
	bool splice;
	int aws_fd;         // fd to S3 connection
	bool kernel_tls;    // Is kernel TLS being used.
};

/**
 * Release resources.
 */
void config_release(struct config *config)
{
	int ret = 0;
	// Free memory
	free(config->file);
	free(config->bucket);
	free(config->region);
	free(config->path);
	free(config->urlencoded_path);
	free(config->hostname);
	free(config->aws_day_date);
	free(config->aws_date_time);
	free(config->http_date);
	free(config->auth_header);
	free(config->http_header);
	// Close fd for file
	if (config->file_fd > 0) {
		close(config->file_fd);
	}
	// shutdown ssl connection - before ctx
	if (config->ssl != NULL) {
		ret = SSL_get_shutdown(config->ssl);
		if (ret >= 0) {
			SSL_shutdown(config->ssl);
		}
		SSL_free(config->ssl);
	}
	// Free ctx must be after any connections
	if (config->ssl_ctx != NULL) {
		SSL_CTX_free(config->ssl_ctx);
	}

	if (config->aws_fd > 0) {
		close(config->aws_fd);
	}
}

/**
 * Crash on OOM
 */
void *xmalloc(size_t size)
{
	void *ptr = malloc(size);
	assert(ptr != NULL);
	return ptr;
}

/**
 * Convert bytes to lowercase base 16 encoding - used in AWS signature.
 */
int to_hex(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
	size_t i;
	assert(out_len >= (2 * in_len + 1));

	for (i = 0; i < in_len; i++) {
		out[i * 2] = "0123456789abcdef"[in[i] >> 4];
		out[i * 2 + 1] = "0123456789abcdef"[in[i] & 0x0F];
	}
	out[in_len * 2] = '\0';

	return 2 * in_len + 1;
}

/**
 * SHA256 digest of bytes in lowercase base 16 encoding
 */
int sha256_hex(const char *in, size_t in_len, char *out, size_t out_len)
{
	int ret = 0;
	unsigned char hash[EVP_MD_size(EVP_sha256())];
	uint32_t digest_size;

	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	assert(mdctx != NULL);
	ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	assert(ret == 1);
	ret = EVP_DigestUpdate(mdctx, in, in_len);
	assert(ret == 1);
	ret = EVP_DigestFinal_ex(mdctx, hash, &digest_size);
	assert(ret == 1);
	EVP_MD_CTX_destroy(mdctx);

	return to_hex(hash, digest_size, out, out_len);
}

/**
 * Generate HMAC SHA256
 */
uint32_t hmac_256(unsigned char *key, int key_size, char *string_to_sign,
		  unsigned char *out_buffer, uint32_t out_len)
{
	assert(out_len >= 32);
	uint32_t digest_size = 0;

	HMAC(EVP_sha256(), key, key_size,
	     (unsigned char *)string_to_sign, strlen(string_to_sign),
	     out_buffer, &digest_size);
	assert(digest_size == 32);
	return digest_size;
}

/**
 * Check user has set credentials in env variables.
 * Seesion token is only needed for short term credentials.
 */
int config_credentials(struct config *config)
{
	int ret = 0;
	config->aws_access_key_id = getenv("AWS_ACCESS_KEY_ID");
	config->aws_secret_access_key = getenv("AWS_SECRET_ACCESS_KEY");
	config->aws_session_token = getenv("AWS_SESSION_TOKEN");

	if (config->aws_access_key_id == NULL
	    || config->aws_secret_access_key == NULL) {
		printf
		    ("AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set in environment variables.\n");
		ret = -1;
	}

	return ret;
}

/**
 * Check file, get size and a fd for it.
 */
int config_file(struct config *config)
{
	int ret = 0;
	int fd = 0;
	struct stat stat;

	fd = open(config->file, O_RDONLY);
	if (fd == -1) {
		printf("Failed to open [%s], %s\n", config->file,
		       strerror(errno));
		ret = -1;
		goto err;
	}

	ret = fstat(fd, &stat);
	if (ret == -1) {
		printf("Failed to stat [%s], %s\n", config->file,
		       strerror(errno));
		close(fd);
		goto err;
	}
	config->file_size = stat.st_size;
	config->file_fd = fd;

err:
	return ret;
}

/**
 * Generate a hostname from bucket and S3 region.
 */
void config_hostname(struct config *config)
{
	uint32_t ret = 0;
	char *template = "%s.s3.%s.amazonaws.com";
	uint32_t required_space = strlen(template) + strlen(config->bucket)
	    + strlen(config->region);

	config->hostname = xmalloc(required_space);
	memset(config->hostname, 0, required_space);
	ret =
	    snprintf(config->hostname, required_space, "%s.s3.%s.amazonaws.com",
		     config->bucket, config->region);
	assert(ret < required_space);
	return;
}

/**
 * Need to urlencode the key - do not encode '/'
 */
void *urlencode_key(const char *path)
{
	uint32_t required_space = 3 * strlen(path) + 1;
	void *encoded_path = xmalloc(required_space);
	char *ptr = encoded_path;

	memset(encoded_path, 0, required_space);
	for (; *path; path++) {
		// Note we do not encode '/'
		// From - https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
		// Encode the forward slash character, '/', everywhere except in the object key name. 
		// For example, if the object key name is photos/Jan/sample.jpg, 
		// the forward slash in the key name is not encoded.
		if (isalnum(*path) || *path == '/' || *path == '~'
		    || *path == '-' || *path == '.' || *path == '_') {
			*ptr = *path;
			ptr++;
		} else {
			sprintf(ptr, "%%%02X", *path);
			ptr += 3;
		}
	}
	return encoded_path;
}

/**
 * Create a path for the HTTP request, ie starts with /.
 * Urlencode path for signing.
 */
void config_path(struct config *config)
{
	char *ptr = NULL;
	char *dst;
	uint32_t required_space = strlen(config->file) + 2;

	config->path = xmalloc(required_space);
	memset(config->path, 0, required_space);

	// Copy file to path, but skip leading 
	// '.' and '/'.
	ptr = config->file;
	dst = config->path;
	// start path with /
	*dst = '/';
	dst++;
	while (*ptr == '.' || *ptr == '/') {
		ptr++;
	}
	while (*ptr) {
		*dst++ = *ptr++;
	}

	config->urlencoded_path = urlencode_key(config->path);
	return;
}

/**
 * Need 3 versions of the date, 2 for the signature
 * and one for the HTTP Date Header.
 */
void config_date(struct config *config)
{
	int ret = 0;
	time_t now;

	// date time in 3 formats.
	config->aws_day_date = xmalloc(DATE_BUFFER_SIZE);
	memset(config->aws_day_date, 0, DATE_BUFFER_SIZE);

	config->aws_date_time = xmalloc(DATE_BUFFER_SIZE);
	memset(config->aws_date_time, 0, DATE_BUFFER_SIZE);

	config->http_date = xmalloc(DATE_BUFFER_SIZE);
	memset(config->http_date, 0, DATE_BUFFER_SIZE);

	time(&now);
	ret = strftime(config->aws_day_date, DATE_BUFFER_SIZE,
		       "%Y%m%d", gmtime(&now));
	assert(ret < DATE_BUFFER_SIZE);

	ret = strftime(config->aws_date_time, DATE_BUFFER_SIZE,
		       "%Y%m%dT%H%M%SZ", gmtime(&now));
	assert(ret < DATE_BUFFER_SIZE);

	ret = strftime(config->http_date, DATE_BUFFER_SIZE,
		       "%a, %d %b %Y %H:%M:%S %Z", gmtime(&now));
	assert(ret < DATE_BUFFER_SIZE);

	return;
}

/**
 * A signing key is created by repeating HMAC-SHA256
 * a couple if times, starting with secret key.
 *
 * DateKey              = HMAC-SHA256("AWS4" + "<SecretAccessKey>"."<yyyymmdd>")
 * DateRegionKey        = HMAC-SHA256(DateKey."<aws-region>")
 * DateRegionServiceKey = HMAC-SHA256(DateRegionKey."<aws-service>")
 * SigningKey           = HMAC-SHA256(DateRegionServiceKey."aws4_request")
 */
void config_signing_key(struct config *config)
{
	assert(config->aws_day_date != NULL);
	assert(config->region != NULL);
	assert(config->aws_secret_access_key != NULL);

	uint32_t key_size = 0;
	unsigned char *buffer = NULL;
	uint32_t buffer_size = 0;
	char *AWS4 = "AWS4";

	// Hold the intermediate keys
	unsigned char DateKey[EVP_MAX_MD_SIZE];
	unsigned char DateRegionKey[EVP_MAX_MD_SIZE];
	unsigned char DateRegionServiceKey[EVP_MAX_MD_SIZE];

	// Create the first key from "AWS4" and AWS_SECRET_ACCESS_KEY
	buffer_size = strlen(AWS4) + strlen(config->aws_secret_access_key);
	buffer = xmalloc(buffer_size);
	memset(buffer, 0, buffer_size);
	memcpy(buffer, AWS4, strlen(AWS4));
	memcpy(buffer + strlen(AWS4), config->aws_secret_access_key,
	       strlen(config->aws_secret_access_key));

	key_size =
	    hmac_256(buffer, buffer_size, config->aws_day_date, DateKey,
		     EVP_MAX_MD_SIZE);
	key_size =
	    hmac_256(DateKey, key_size, config->region, DateRegionKey,
		     EVP_MAX_MD_SIZE);
	key_size =
	    hmac_256(DateRegionKey, key_size, "s3", DateRegionServiceKey,
		     EVP_MAX_MD_SIZE);
	key_size =
	    hmac_256(DateRegionServiceKey, key_size, "aws4_request",
		     config->signing_key, EVP_MAX_MD_SIZE);
	config->signing_key_size = key_size;

	free(buffer);
}

/**
 * Need to generate an Authentication Header value.
 *
 * First create a Canonical Request (this includes
 * HTTP method, host header and x-amz headers). Only
 * support one optional x-amz header for session
 * token.
 *
 * Once canonical header is created, take 
 * SHA256 Diagest of it and create a signing
 * request.
 *
 * This string is signed using the generated
 * signing key and an Authentication header
 * is created.
 *
 * Note - we do not create a SHA256 of
 * the file contents. If we plan to use 
 * kernel TLS and sendfile then we will not
 * see the contents of the file, the
 * optimisation is to not copy the data in
 * and out of user space - so we cannot 
 * calculate the SHA256 of the file contents.
 *
 */
void config_auth_header(struct config *config)
{
	// We have two templates for Canonical
	// request. One has the session token
	// the other does not.
	char *template_no_session_token =
	    "PUT\n"
	    "%s\n"
	    "\n"
	    "host:%s\n"
	    "x-amz-content-sha256:UNSIGNED-PAYLOAD\n"
	    "x-amz-date:%s\n"
	    "\n" "host;x-amz-content-sha256;x-amz-date\n" "UNSIGNED-PAYLOAD";

	char *template_with_session_token =
	    "PUT\n"
	    "%s\n"
	    "\n"
	    "host:%s\n"
	    "x-amz-content-sha256:UNSIGNED-PAYLOAD\n"
	    "x-amz-date:%s\n"
	    "x-amz-security-token:%s\n"
	    "\n"
	    "host;x-amz-content-sha256;x-amz-date;x-amz-security-token\n"
	    "UNSIGNED-PAYLOAD";

	char *string_to_sign =
	    "AWS4-HMAC-SHA256\n" "%s\n" "%s/%s/s3/aws4_request\n" "%s";

	char buffer[FOUR_K];
	char canonical_request_digest[DIGEST_SIZE];
	unsigned char signature_bytes[EVP_MAX_MD_SIZE];
	char signature_hex[DIGEST_SIZE];
	uint32_t size;

	#define BUF_APPEND(buffer, s) \
			assert(size + strlen(s) < FOUR_K); \
			memcpy(buffer + size, s, strlen(s)); \
			size += strlen(s);

	// Create Canonical Request
	memset(buffer, 0, FOUR_K);
	if (config->aws_session_token == NULL) {
		size = snprintf(buffer, FOUR_K, template_no_session_token,
				config->urlencoded_path, config->hostname,
				config->aws_date_time);
		assert(size < FOUR_K);
	} else {
		size = snprintf(buffer, FOUR_K, template_with_session_token,
				config->urlencoded_path, config->hostname,
				config->aws_date_time,
				config->aws_session_token);
		assert(size < FOUR_K);
	}
	// Store the Canonical Request digest in hex.
	memset(canonical_request_digest, 0, DIGEST_SIZE);
	sha256_hex(buffer, size, canonical_request_digest, DIGEST_SIZE);

	// Reset buffer to hold String To Sign and generate.
	memset(buffer, 0, FOUR_K);
	size = snprintf(buffer, FOUR_K, string_to_sign,
			config->aws_date_time, config->aws_day_date,
			config->region, canonical_request_digest);
	assert(size < FOUR_K);

	// Now sign the String To Sign that is in the buffer.
	size = hmac_256(config->signing_key, config->signing_key_size, buffer,
			signature_bytes, EVP_MAX_MD_SIZE);
	memset(signature_hex, 0, DIGEST_SIZE);
	to_hex(signature_bytes, size, signature_hex, DIGEST_SIZE);

	// Reset buffer to create Authentication Header value
	// and store in config.
	memset(buffer, 0, FOUR_K);
	char *auth_header_template =
	    "AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date";
	size = snprintf(buffer, FOUR_K, auth_header_template,
			config->aws_access_key_id, config->aws_day_date,
			config->region);
	assert(size < FOUR_K);

	// If there is a session token need to include it.
	if (config->aws_session_token != NULL) {
		BUF_APPEND(buffer, ";x-amz-security-token");
	}

	BUF_APPEND(buffer, ",Signature=");
	BUF_APPEND(buffer, signature_hex);

	// Take copy of buffer.
	config->auth_header = strdup(buffer);
}

/**
 * Create the HTTP Header.
 */
void config_http_header(struct config *config)
{
	uint32_t size;
	char buffer[FOUR_K];
	char *http_header_template =
	    "PUT %s HTTP/1.1\r\n"
	    "Content-Length: %ld\r\n"
	    "Host: %s\r\n"
	    "Date: %s\r\n"
	    "Connection: closed\r\n"
	    "Authorization: %s\r\n"
	    "x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n" "x-amz-date: %s\r\n";

	memset(buffer, 0, FOUR_K);
	size = snprintf(buffer, FOUR_K, http_header_template,
			config->path, config->file_size,
			config->hostname, config->http_date,
			config->auth_header, config->aws_date_time);
	assert(size < FOUR_K);
	// May need to include session token header.
	if (config->aws_session_token != NULL) {
		size +=
		    snprintf(buffer + size, FOUR_K - size,
			     "x-amz-security-token: %s\r\n\r\n",
			     config->aws_session_token);
		assert(size < FOUR_K);
	} else {
		assert(size + strlen("\r\n") < FOUR_K);
		memcpy(buffer + size, "\r\n", strlen("\r\n"));
	}

	config->http_header = strdup(buffer);
	return;
}

/**
 * Do basic configuration. 
 */
int config_setup(struct config *config)
{
	int ret = 0;

	if (config->file == NULL || strlen(config->file) == 0) {
		printf("File option must be set.\n");
		ret = -1;
		goto err;
	}
	if (config->bucket == NULL || strlen(config->bucket) == 0) {
		printf("Bucket option must be set.\n");
		ret = -1;
		goto err;
	}
	if (config->region == NULL || strlen(config->region) == 0) {
		printf("Region option must be set.\n");
		ret = -1;
		goto err;
	}
	ret = config_credentials(config);
	if (ret != 0) {
		goto err;
	}
	ret = config_file(config);
	if (ret != 0) {
		goto err;
	}
	config_hostname(config);
	config_path(config);
	config_date(config);
	config_signing_key(config);
	config_auth_header(config);
	config_http_header(config);

err:
	return ret;
}

/**
 * Set up the SSL Context.
 */
int config_ssl(struct config *config)
{
	int ret = 0;
	int ret_t = 0;

	ERR_clear_error();

	config->ssl_ctx = SSL_CTX_new(TLS_client_method());
	assert(config->ssl_ctx != NULL);

	// Turn a closed connection into a normal close rather than SSL error
	SSL_CTX_set_options(config->ssl_ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
	// Do not allow TLS 1.2 renegotiaiton.
	SSL_CTX_set_options(config->ssl_ctx, SSL_OP_NO_RENEGOTIATION);

	// KTLS on most kernels support this version.
	// https://www.nginx.com/blog/improving-nginx-performance-with-kernel-tls/
	SSL_CTX_set_min_proto_version(config->ssl_ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(config->ssl_ctx, TLS1_2_VERSION);

	// User Kernel TLS
	SSL_CTX_set_options(config->ssl_ctx, SSL_OP_ENABLE_KTLS);

	// Limit to one cipher, this is supported in CPU hardware
	// so fast. Its also supported by kernel.
	// Note - this is the TLS 1.2 cipher setup function.
	ret_t = SSL_CTX_set_cipher_list(config->ssl_ctx,
			"ECDHE-RSA-AES128-GCM-SHA256");
	assert(ret_t == 1);

	// Load certs - Ubuntu Specific Location here.
	ret_t = SSL_CTX_load_verify_locations(config->ssl_ctx,
					      "/etc/ssl/certs/ca-certificates.crt",
					      "/etc/ssl/certs");
	if (ret_t != 1) {
		printf
		    ("Failed to load CA from /etc/ssl/certs/ca-certificates.crt and /etc/ssl/certs\n");
		ret = -1;
		goto err;
	}

err:
	return ret;
}



int submit_and_wait(struct io_uring *ring, int *res)
{
        struct io_uring_cqe *cqe;
        int ret;

        ret = io_uring_submit_and_wait(ring, 1);
        if (ret != 1) {
                fprintf(stderr, "io_using_submit: got %d\n", ret);
                return 1;
        }

        ret = io_uring_peek_cqe(ring, &cqe);
        if (ret) {
                fprintf(stderr, "io_uring_peek_cqe(): no cqe returned");
                return 1;
        }

        *res = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        return 0;
}



int wait_for(struct io_uring *ring, int fd, int mask)
{
        struct io_uring_sqe *sqe;
        int ret, res;

        sqe = io_uring_get_sqe(ring);
        if (!sqe) {
                fprintf(stderr, "unable to get sqe\n");
                return -1;
        }

        io_uring_prep_poll_add(sqe, fd, mask);
        sqe->user_data = 2;

        ret = submit_and_wait(ring, &res);
        if (ret)
                return -1;

        if (res < 0) {
                fprintf(stderr, "poll(): failed with %d\n", res);
                return -1;
        }

        return res;
}

int do_uring_basic_connect(struct config *config, struct io_uring *ring, 
		          struct addrinfo *servinfo) 
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int code;
	int ret;
	int res;
	socklen_t code_len = sizeof(code);

	sqe = io_uring_get_sqe(ring);
        if (!sqe) {
                fprintf(stderr, "unable to get sqe\n");
                return -1;
        }
        
	io_uring_prep_connect(sqe, config->aws_fd, servinfo->ai_addr, servinfo->ai_addrlen);
        sqe->user_data = 1;
  
	ret = io_uring_submit_and_wait(ring, 1);
        if (ret != 1) {
                fprintf(stderr, "io_using_submit: got %d\n", ret);
                return -1;
        }
	
	ret = io_uring_peek_cqe(ring, &cqe);
        if (ret) {
                fprintf(stderr, "io_uring_peek_cqe(): no cqe returned");
                return -1;
        }

	res = cqe->res;
        io_uring_cqe_seen(ring, cqe);

	if (res == -EINPROGRESS) {
		ret = wait_for(ring, config->aws_fd, POLLOUT | POLLHUP | POLLERR);
                if (ret == -1)
                        return -1;

                int ev = (ret & POLLOUT) || (ret & POLLHUP) || (ret & POLLERR);
                if (!ev) {
                        fprintf(stderr, "poll(): returned invalid value %#x\n", ret);
                        return -1;
                }

                ret = getsockopt(config->aws_fd, SOL_SOCKET, SO_ERROR, &code, &code_len);
                if (ret == -1) {
                        perror("getsockopt()");
                        return -1;
                }
	} else {
		fprintf(stderr, "connect failed with %d\n", res);
	}
	return 0;
}


/**
 * Do the basic TCP connection, resolve hostname
 * and try to connect. When resolving hostname
 * we might get multiple IP addresses but we only
 * use one.
 */
int do_basic_connect(struct config *config, struct io_uring *ring)
{
	int ret = 0;
	struct addrinfo hints;
	struct addrinfo *servinfo = NULL;;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(config->hostname, "https", &hints, &servinfo);
	if (ret != 0) {
		printf("Failed to resolve [%s]. %s\n", config->hostname,
		       gai_strerror(ret));
		ret = -1;
		goto err;
	}
	// Use first address - could cycle through them to find one
	// that works if we hit an issue.
	config->aws_fd = socket(servinfo->ai_family, servinfo->ai_socktype,
				servinfo->ai_protocol);
	assert(config->aws_fd > 0);

	ret = do_uring_basic_connect(config, ring, servinfo);
	if (ret != 0) {
                printf("Failed to connect %s\n", strerror(errno));
                ret = -1;
        }

err:
	if (servinfo != 0) {
		freeaddrinfo(servinfo);
	}

	return ret;
}

/**
 * Upgrade the TCP connection to SSL connection. 
 * Limited handling of errors other than reporting
 * and exiting.
 */
int do_ssl_connect(struct config *config)
{
	int ret = 0;
	int ret_t = 0;
	char error_holder[128];
	int ssl_err = 0;
	int my_errno = 0;
	int ssl_read = 0;
	int ssl_write = 0;

	config->ssl = (SSL *) SSL_new(config->ssl_ctx);
	assert(config->ssl != NULL);

	ret_t = SSL_set_fd(config->ssl, config->aws_fd);
	assert(ret_t == 1);

	// To enable SSL debug to stdout
	if (config->ssl_debug) {
		SSL_set_msg_callback(config->ssl, SSL_trace);
        	SSL_set_msg_callback_arg(config->ssl, BIO_new_fp(stdout,0));
	}

	ret_t = SSL_connect(config->ssl);
	if (ret_t != 1) {
		my_errno = errno;
		ssl_err = SSL_get_error(config->ssl, ret_t);
		memset(error_holder, 0, 128);
		ERR_error_string_n(ERR_get_error(), error_holder, 128);
		printf("Failed to connect errno [%s], ssl_err[%d], %s\n",
		       strerror(my_errno), ssl_err, error_holder);
		ret = -1;
	}
	// Check it KTLS is being used.
	ssl_write = BIO_get_ktls_send(SSL_get_wbio(config->ssl));
	ssl_read = BIO_get_ktls_recv(SSL_get_rbio(config->ssl));
	if (ssl_write && ssl_read) {
		config->kernel_tls = true;
	}

	return ret;
}

/**
 * Write HTTP header - we assume SSL will accept it in one
 * write.
 */
int do_write_http_header(struct config *config)
{
	int ret = 0;
	int ret_t = 0;
	char error_holder[128];
	int ssl_err = 0;
	int my_errno = 0;

	// header < 16K, the SSL record size so it should consume it all
	printf("HTTP Request Header>>>>>\n%s\n<<<<<<Header\n", config->http_header);
	ret_t =
	    SSL_write(config->ssl, config->http_header,
		      strlen(config->http_header));
	if (ret_t != (int)strlen(config->http_header)) {
		my_errno = errno;
		printf("Failed to write complete HTTP Headers, wrote [%d]\n",
		       ret_t);
		ssl_err = SSL_get_error(config->ssl, ret_t);
		memset(error_holder, 0, 128);
		ERR_error_string_n(ERR_get_error(), error_holder, 128);
		printf("Failed to write errno [%s], ssl_err[%d], %s\n",
		       strerror(my_errno), ssl_err, error_holder);
		ret = -1;
	}

	return ret;
}

/**
 * Read file and write to S3, use 16K buffer as that is
 * the SSL record size. This does not use sendfile -
 * uses SSL_write
 */
int do_write_file(struct config *config)
{
	int ret = 0;
	int32_t ret_t = 0;
	size_t to_write = 0;
	size_t written = 0;
	int64_t total_read = 0;
	char error_holder[128];
	int ssl_err;
	int my_errno;
	char write_buffer[SIXTEEN_K];

	do {
		ret_t = read(config->file_fd, write_buffer, SIXTEEN_K);
		if (ret_t == 0) {
			// EOF
			break;
		}
		if (ret_t == -1) {
			// Error
			printf("Failed to read from file %s, %s\n",
			       config->file, strerror(errno));
			ret = -1;
			goto err;
		}
		total_read += ret_t;
		to_write = ret_t;
		written = 0;
		do {
			ret_t =
			    SSL_write(config->ssl, write_buffer + written,
				      to_write - written);
			if (ret_t <= 0) {
				my_errno = errno;
				ssl_err = SSL_get_error(config->ssl, ret_t);
				memset(error_holder, 0, 128);
				ERR_error_string_n(ERR_get_error(),
						   error_holder, 128);
				printf
				    ("Failed to connect errno [%s], ssl_err[%d], %s\n",
				     strerror(my_errno), ssl_err, error_holder);
				ret = -1;
				goto err;
			}
			written += ret_t;
		} while (written < to_write);
	} while (total_read < config->file_size);

err:
	return ret;
}


/**
 * Splice data from file to socket using io_uring. Internally
 * sendfile uses splice in the kernel, using io_uring allows
 * use to do this asynchronously (there is no asynchronous 
 * sendfile). The value of this approach when there are multiple
 * files to be upload - a single thread can drive uploads and
 * the number of system calls can be reduced as mutliple splices
 * can be done through a single io_uring submit.
 *  
 * io_uring can chain commands together. 
 */
int do_splice(struct config *config, struct io_uring *ring)
{
	int ret = 0;
	int pipefd[2];
	off_t len;
	off_t file_offset = 0;
	off_t block_size = 1 << 14;
	off_t buf_size = 0;
	off_t read_size = 0;
	struct io_uring_cqe *cqe;
        struct io_uring_sqe *sqe;


	// Splice works by splicing data from the file fd into a 
	// pipe, then splicing the data from the pipe into the socket.
	// Essentially the pipe is a pointer to a memory buffer in
	// the kernel - optimally the kernel will support DMA so there
	// is zero copy.
	if (pipe(pipefd) < 0) {
		printf("Failed to create pipe: %s", strerror(errno));
		ret = -1;
		goto out;
	}	

	len = config->file_size;
	// Loop over then length of the file splicing a chunk of
	// data into the pipe and then splice it from the pipe into
	// the socket. 
	// This is a naive implementation - we could request the kernel
	// splice multiple chunks at a time and allow the kernel to
	// optimally manage when it does the splices.  
	// Also can chain the commands together and busy poll.
	while (len) {
		// How much do we want to splice?
		buf_size = len < block_size ? len : block_size;
		// Get an SQE to submit to the ring.
		sqe = io_uring_get_sqe(ring);
                if (!sqe) {
                        fprintf(stderr, "get sqe failed\n");
                        ret = -1;
			goto err;
                }
		// Prepare a splice request
		io_uring_prep_splice(sqe, config->file_fd, file_offset, pipefd[1], -1,
                                     buf_size, 0);
		// We can supply data in the sqe that will be returned to us in the 
		// cqe - this could be a pointer to a state machine that manages the
		// process for this file allowing multiple files to be done in parallel.
                sqe->user_data = 42;
                sqe->opcode = IORING_OP_SPLICE;

		// Submit request.
		ret = io_uring_submit(ring);
                if (ret != 1) {
                        fprintf(stderr, "sqe submit failed: %d\n", ret);
                        ret = -1;
			goto err;
                }

		// Now block waiting for stuff to happen - the thread could
		// go off and do other stuff and poll the ring instead.
                ret = io_uring_wait_cqe(ring, &cqe);
                if (ret < 0) {
                        fprintf(stderr, "wait completion %d\n", cqe->res);
                        ret = -1;
			goto err;
                }

		if (cqe->res <= 0) {
			// io_uring sets the cqe-res as -errno if there is an error 
			fprintf(stderr, "Splice to pipe failed: %s.\n", strerror(-cqe->res));
                        ret = cqe->res;
                        io_uring_cqe_seen(ring, cqe);
			goto err;
                }
		len -= cqe->res;
		file_offset += cqe->res;
		read_size = cqe->res;
		printf("Spliced %ld bytes to pipe from file.\n", read_size);
		io_uring_cqe_seen(ring, cqe);

		// Now send what has been put into the pipe into the socket. We
		// drain the whole pipe.
		while (read_size) {
			sqe = io_uring_get_sqe(ring);
                	if (!sqe) {
                        	fprintf(stderr, "get sqe failed\n");
                        	return -1;
                	}
                	io_uring_prep_splice(sqe, pipefd[0], -1, config->aws_fd, -1,
                                     read_size, 0);
                	sqe->user_data = 42;
                	sqe->opcode = IORING_OP_SPLICE;

			ret = io_uring_submit(ring);
                	if (ret != 1) {
                        	fprintf(stderr, "sqe submit failed: %d\n", ret);
                        	ret = -1;
				goto err;
                	}

                	ret = io_uring_wait_cqe(ring, &cqe);
                	if (ret < 0) {
                        	fprintf(stderr, "wait completion %d\n", cqe->res);
                        	ret = -1;
				goto err;
                	}

			if (cqe->res <= 0) {
				// io_uring sets the cqe-res as -errno if there is an error 
				fprintf(stderr, "Splice to socket failed: %s.\n", 
						strerror(-cqe->res));
                        	ret = cqe->res;
                        	io_uring_cqe_seen(ring, cqe);
				goto err;
                	}
			read_size -= cqe->res;
			printf("Spliced %d pipes from pipe to socket\n", cqe->res);
			io_uring_cqe_seen(ring, cqe);
		}
	}
	
	
err:
	close(pipefd[0]);
	close(pipefd[1]);
out:	
	return ret;
}


/**
 * If using Kernel TLS can use sendfile.
 */
int do_sendfile(struct config *config)
{
	int ret = 0;
	size_t ret_t = 0;
	size_t to_write = 0;
	off_t offset = 0;
	// https://www.kernel.org/doc/html/latest/networking/tls.html
	// The sendfile system call will send the file’s data over TLS records of maximum length (2^14).
	size_t sendfile_buffer_size = 2 << 14;

	size_t remaining = config->file_size;
	while (remaining > 0) {
		if (remaining < sendfile_buffer_size) {
			to_write = remaining;
		} else {
			to_write = sendfile_buffer_size;
		}
		ret_t =
		    // Should use SSL_sendfile which will do the correct
		    // thing whether kTLS is working or not. This allows
		    // us to see that kTLS is working.
		    sendfile(config->aws_fd, config->file_fd, &offset,
			     to_write);
		if ((int)ret_t == -1) {
			printf("Failed to sendfile, %s\n", strerror(errno));
			ret = -1;
			goto err;
		}
		remaining -= ret_t;
		printf("Sendfile sent [%ld], [%ld] remaining.\n",
		       ret_t, remaining);
	}

err:
	return ret;
}

/**
 * Dumb reading, simply read and write to stdout.
 * We sent Connection: close header so server
 * should close connection when it is done
 * and tigger an exit from here.
 */
int read_response(struct config *config)
{
	int ret = 0;
	int ret_t = 0;
	char response[SIXTEEN_K];
	char error_holder[128];
	int ssl_err;
	int my_errno;

	while (true) {
		memset(response, 0, SIXTEEN_K);
		ret_t = SSL_read(config->ssl, response, SIXTEEN_K);
		if (ret_t < 0) {
			my_errno = errno;
			ssl_err = SSL_get_error(config->ssl, ret_t);
			memset(error_holder, 0, 128);
			ERR_error_string_n(ERR_get_error(), error_holder, 128);
			printf("Failed to read errno [%s], ssl_err[%d], %s\n",
			       strerror(my_errno), ssl_err, error_holder);
			ret = -1;
			goto err;
		}
		if (ret_t == 0) {
			// Connection closed.
			break;
		}
		printf("Response>>>>\n%.*s\n<<<<Response\n", SIXTEEN_K,
		       response);
	}

err:
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	struct config config;
	int option_index = 0;
	int c = 0;
	struct io_uring ring;

        ret = io_uring_queue_init(8, &ring, 0);
        if (ret) {
                fprintf(stderr, "io_uring_queue_setup() = %d\n", ret);
                return -1;
        }


	memset(&config, 0, sizeof(struct config));

	// User must provide 
	//  file to upload
	//  region to use
	//  bucket to use.
	// Credentials will be retrieved from env.
	while (1) {
		static struct option long_options[] = {
			{ "file", required_argument, 0, 'a' },
			{ "bucket", required_argument, 0, 'b' },
			{ "region", required_argument, 0, 'c' },
			{ "ssl_debug", no_argument, 0, 'd' },
			{ "splice", no_argument, 0, 's' },
			{ 0, 0, 0, 0 }
		};
		/* getopt_long stores the option index here. */

		c = getopt_long(argc, argv, "", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			config.file = strdup(optarg);
			break;

		case 'b':
			config.bucket = strdup(optarg);
			break;

		case 'c':
			config.region = strdup(optarg);
			break;

		case 'd':
			printf("TLS debug enabled.\n");
			config.ssl_debug = true;
			break;

		case 's':	
			printf("Using io_uring splice.\n");
			config.splice = true;
			break;

		case '?':
			/* getopt_long already printed an error message. */
			break;

		default:
			goto err;
		}
	}

	// Prepare SSL library
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	ERR_clear_error();

	// Basic check of config and setup.
	ret = config_setup(&config);
	if (ret != 0) {
		printf("Configuration setup failed.\n");
		goto err;
	}
	// Get SSL setup.
	ret = config_ssl(&config);
	if (ret != 0) {
		printf("SSL configuration setup failed.\n");
		goto err;
	}
	// TCP connection to S3
	// This is done using io_uring.
	ret = do_basic_connect(&config, &ring);
	if (ret != 0) {
		printf("Basic connect failed.\n");
		goto err;
	}
	printf("TCP connection complete.\n");
	// Upgrade to SSL connection.
	// Nearly everything can be turned into io_uring requests
	// that can be done asynchronously (open the file, close
	// the file etc) but the SSL connect uses the openssl library
	// which is a blocking call ATM, would need to break this
	// down and manage the handshake through exchange of data
	// and io_uring.
	ret = do_ssl_connect(&config);
	if (ret != 0) {
		printf("SSL connect failed.\n");
		goto err;
	}
	printf("SSL handshake complete.\n");
	// Write HTTP header
	ret = do_write_http_header(&config);
	if (ret != 0) {
		printf("Write of HTTP Headers failed.\n");
		goto err;
	}
	printf("HTTP headers sent.\n");
	// Write the body.
	if (config.kernel_tls && config.splice) {
		printf("Kernal TLS enabled, using splice.\n");
		ret = do_splice(&config, &ring);
	} else if (config.kernel_tls) {	
		printf("Kernal TLS enabled, using sendfile.\n");
		ret = do_sendfile(&config);
	} else {
		printf("Kernal TLS Not enabled, using SSL_write..\n");
		ret = do_write_file(&config);
	}
	if (ret != 0) {
		printf("Write of file failed.\n");
		goto err;
	}
	printf("File contents sent.\n");
	// Read what comes back and dump to stdout.
	ret = read_response(&config);
	if (ret != 0) {
		printf("Read response failed..\n");
		goto err;
	}
	printf("Server response read, connection closed.\n");

err:
	config_release(&config);
	ERR_free_strings();
	io_uring_queue_exit(&ring);
	return ret;
}
