/*
 * Copyright (C) 2006, 2008 Valery Kholodkov
 * Client body reception code Copyright (c) 2002-2007 Igor Sysoev
 * Temporary file name generation code Copyright (c) 2002-2007 Igor Sysoev
 */
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
}
#include <vector>
#include <string>
#include <sstream>

#include <iostream>
#include "structs.h"
#include "action_upload.h"
#include "base3/logging.h"
#include "base3/sysloging.h"
#include "blockmanage.h"
#include "tickmanager.h"
#include "cross_domain.h"
#include "arch_diff/site_xiaonei.h"

using namespace upload;
#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif

#define MULTIPART_FORM_DATA_STRING              "multipart/form-data"
#define OCTET_STREAM_STRING                     "application/octet-stream"
#define URLENCODED_STRING                       "application/x-www-form-urlencoded"
#define BOUNDARY_STRING                         "boundary="
#define CONTENT_DISPOSITION_STRING              "Content-Disposition:"
#define CONTENT_TYPE_STRING                     "Content-Type:"
#define CONTENT_RANGE_STRING                    "Content-Range:"
#define X_CONTENT_RANGE_STRING                  "X-Content-Range:"
#define SESSION_ID_STRING                       "Session-ID:"
#define X_SESSION_ID_STRING                     "X-Session-ID:"
#define FORM_DATA_STRING                        "form-data"
#define ATTACHMENT_STRING                       "attachment"
#define FILENAME_STRING                         "filename=\""
#define FIELDNAME_STRING                        "name=\""
#define BYTES_UNIT_STRING                       "bytes "

#define PAGETYPE "pagetype"
#define HOSTID "hostid"
#define UPLOADID "uploadid"
#define TICK "tick"
#define BLOCK_INDEX "block_index"
#define BLOCK_COUNT "block_count"

#define NGX_UPLOAD_MALFORMED    -1
#define NGX_UPLOAD_NOMEM        -2
#define NGX_UPLOAD_IOERROR      -3
#define NGX_UPLOAD_SCRIPTERROR  -4
#define NGX_UPLOAD_TOOLARGE     -5

/*
 * State of multipart/form-data parser
 */
typedef enum {
	upload_state_boundary_seek,
	upload_state_after_boundary,
	upload_state_headers,
	upload_state_data,
	upload_state_finish
} upload_state_t;

/*
 * Range
 */
typedef struct {
    off_t       start, end, total;
} ngx_http_upload_range_t;

/*
 * State of range merger
 */
typedef struct {
    ngx_buf_t               *in_buf;
    ngx_buf_t               *out_buf;
    ngx_http_upload_range_t  current_range_n;
    off_t                   *parser_state;
    ngx_log_t               *log;

    u_char                  *range_header_buffer;
    u_char                  *range_header_buffer_end;
    u_char                  **range_header_buffer_pos;

    unsigned int             found_lower_bound:1;
    unsigned int             complete_ranges:1;
    unsigned int             first_range:1;
} ngx_http_upload_merger_state_t;

/*
 * Template for a field to generate in output form
 */
typedef struct {
    ngx_table_elt_t         value;
    ngx_array_t             *field_lengths;
    ngx_array_t             *field_values;
    ngx_array_t             *value_lengths;
    ngx_array_t             *value_values;
} ngx_http_upload_field_template_t;

/*
 * Filter for fields in output form
 */
typedef struct {
#if (NGX_PCRE)
    ngx_regex_t              *regex;
    ngx_int_t                ncaptures;
#else
    ngx_str_t                text;
#endif
} ngx_http_upload_field_filter_t;

/*
 * Upload cleanup record
 */
typedef struct ngx_http_upload_cleanup_s {
    ngx_fd_t                         fd;
    u_char                           *filename;
    ngx_http_headers_out_t           *headers_out;
    ngx_array_t                      *cleanup_statuses;
    ngx_log_t                        *log;
    unsigned int                     aborted:1;
} ngx_upload_cleanup_t;

/*
 * Upload configuration for specific location
 */
typedef struct {
    ngx_str_t                     url;
    ngx_http_complex_value_t      *url_cv;
    ngx_path_t                    *state_store_path;
    ngx_path_t                    *store_path;
    ngx_uint_t                    store_access;
    size_t                        buffer_size;
    size_t                        merge_buffer_size;
    size_t                        range_header_buffer_size;
    size_t                        max_header_len;
    size_t                        max_output_body_len;
    off_t                         max_file_size;
    ngx_array_t                   *field_templates;
    ngx_array_t                   *aggregate_field_templates;
    ngx_array_t                   *field_filters;
    ngx_array_t                   *cleanup_statuses;
    ngx_flag_t                    forward_args;
    ngx_flag_t                    tame_arrays;
    ngx_flag_t                    resumable_uploads;
    size_t                        limit_rate;

	ngx_http_upstream_conf_t   upstream; //jin.shang

    unsigned int                  md5:1;
    unsigned int                  sha1:1;
    unsigned int                  crc32:1;
} ngx_http_upload_loc_conf_t;

typedef struct ngx_http_upload_md5_ctx_s {
    MD5_CTX     md5;
    u_char      md5_digest[MD5_DIGEST_LENGTH * 2];
} ngx_http_upload_md5_ctx_t;

typedef struct ngx_http_upload_sha1_ctx_s {
    SHA_CTX     sha1;
    u_char      sha1_digest[SHA_DIGEST_LENGTH * 2];
} ngx_http_upload_sha1_ctx_t;

struct ngx_http_upload_ctx_s;

/*
 * Request body data handler
 */
typedef ngx_int_t (*ngx_http_request_body_data_handler_pt)
    (struct ngx_http_upload_ctx_s*, u_char *, u_char*);

/*
 * Upload module context
 */
typedef struct ngx_http_upload_ctx_s {
    ngx_str_t           session_id;
    ngx_str_t           boundary;
    u_char              *boundary_start;
    u_char              *boundary_pos;

    upload_state_t		state;

    u_char              *header_accumulator;
    u_char              *header_accumulator_end;
    u_char              *header_accumulator_pos;

    ngx_str_t           field_name;
    ngx_str_t           file_name;
    ngx_str_t           content_type;
    ngx_str_t           content_range;
    ngx_http_upload_range_t     content_range_n;

    ngx_uint_t          ordinal;

    u_char              *output_buffer;
    u_char              *output_buffer_end;
    u_char              *output_buffer_pos;
    u_char              *merge_buffer;
    u_char              *range_header_buffer;
    u_char              *range_header_buffer_pos;
    u_char              *range_header_buffer_end;

    ngx_http_request_body_data_handler_pt data_handler;

    ngx_int_t (*start_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*finish_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*abort_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
	ngx_int_t (*flush_output_buffer_f)(struct ngx_http_upload_ctx_s *upload_ctx, u_char *buf, size_t len);

    ngx_http_request_t  *request;
    ngx_log_t           *log;

    ngx_file_t          output_file;
    ngx_file_t          state_file;
    ngx_chain_t         *chain;
    ngx_chain_t         *last;
    ngx_chain_t         *checkpoint;
    size_t              output_body_len;
    size_t              limit_rate;
    ssize_t             received;
	u_char *pic;//jin.shang
	ngx_str_t *pagetype;
	ngx_str_t *hostid;
	ngx_str_t *uploadid;
	ngx_str_t *tick;
	ngx_str_t *block_index;
	ngx_str_t *block_count;
	ngx_str_t *cookie;
	ngx_buf_t *temp;
	unsigned int is_octet_stream:1;
	unsigned int is_urlencoded:1;
	

    ngx_pool_cleanup_t          *cln;

    ngx_http_upload_md5_ctx_t   *md5_ctx;    
    ngx_http_upload_sha1_ctx_t  *sha1_ctx;    
    uint32_t                    crc32;    

    unsigned int        first_part:1;
    unsigned int        discard_data:1;
    unsigned int        is_file:1;
    unsigned int        partial_content:1;
    unsigned int        prevent_output:1;
    unsigned int        calculate_crc32:1;
    unsigned int        started:1;
    unsigned int        unencoded:1;
    unsigned int        no_content:1;
    unsigned int        raw_input:1;
} ngx_http_upload_ctx_t;

static std::vector<std::string> images;
//static ProccesserRequest req;
//static ProccesserResponse resp;

static ngx_int_t ngx_http_upload_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_upload_body_handler(ngx_http_request_t *r);

static void *ngx_http_upload_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upload_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_upload_add_variables(ngx_conf_t *cf);
static void ngx_http_upload_variable_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_sha1_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_file_size_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_upload_content_range_variable_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data);
static ngx_int_t ngx_http_upload_content_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data);
static ngx_int_t ngx_http_upload_crc32_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_uint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_upload_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_upload_start_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t *u);

static ngx_int_t ngx_http_upload_flush_output_buffer(ngx_http_upload_ctx_t *u,
    u_char *buf, size_t len);
static ngx_int_t ngx_http_upload_append_field(ngx_http_upload_ctx_t *u,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_upload_merge_ranges(ngx_http_upload_ctx_t *u, ngx_http_upload_range_t *range_n);
static ngx_int_t ngx_http_upload_parse_range(ngx_str_t *range, ngx_http_upload_range_t *range_n);

static void ngx_http_read_upload_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_upload_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_process_request_body(ngx_http_request_t *r, ngx_chain_t *body);

static ngx_int_t ngx_http_read_upload_client_request_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler); //change
//static ngx_int_t ngx_http_read_upload_client_request_body(ngx_http_request_t *r); //ch2

static char *ngx_http_upload_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upload_pass_form_field(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upload_cleanup(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_upload_cleanup_handler(void *data);

/*******************
 *jin.shang
 ******************/
static ngx_int_t ngx_http_upload_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_upload_process_header(ngx_http_request_t *r);
static void ngx_http_upload_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_upload_parse_args(ngx_http_upload_ctx_t *u, u_char *buf, size_t len);
static ngx_int_t upload_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_int_t ngx_http_upload_handler(ngx_http_request_t *r);
static void upload_post_handler(ngx_http_request_t *r);
static char* ngx_conf_set_echo(ngx_conf_t *cf, ngx_command_t *cmd, void* conf);
static ngx_int_t ngx_http_upload_form_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_upload_stream_handler(ngx_http_request_t *r);
static void upload_parse_header_args(ngx_http_request_t *r);
static string num2str(int i);
static ngx_int_t ngx_http_upload_init(ngx_conf_t *cf);


#if defined nginx_version && nginx_version >= 7052
static ngx_path_init_t        ngx_http_upload_temp_path = {
    ngx_string(NGX_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
};
#endif

/*
 * upload_init_ctx
 *
 * Initialize upload context. Memory for upload context which is being passed
 * as upload_ctx parameter could be allocated anywhere and should not be freed
 * prior to upload_shutdown_ctx call.
 *
 * IMPORTANT:
 * 
 * After initialization the following routine SHOULD BE called:
 * 
 * upload_parse_content_type -- to assign part boundary 
 *
 * Parameter:
 *     upload_ctx -- upload context which is being initialized
 * 
 */
static void upload_init_ctx(ngx_http_upload_ctx_t *upload_ctx);

/*
 * upload_shutdown_ctx
 *
 * Shutdown upload context. Discard all remaining data and 
 * free all memory associated with upload context.
 *
 * Parameter:
 *     upload_ctx -- upload context which is being shut down
 * 
 */
static void upload_shutdown_ctx(ngx_http_upload_ctx_t *upload_ctx);

/*
 * upload_start
 *
 * Starts multipart stream processing. Initializes internal buffers
 * and pointers
 *
 * Parameter:
 *     upload_ctx -- upload context which is being initialized
 * 
 * Return value:
 *               NGX_OK on success
 *               NGX_ERROR if error has occured
 *
 */
static ngx_int_t upload_start(ngx_http_upload_ctx_t *upload_ctx, ngx_http_upload_loc_conf_t  *ulcf);

/*
 * upload_parse_request_headers
 *
 * Parse and verify HTTP headers, extract boundary or
 * content disposition
 * 
 * Parameters:
 *     upload_ctx -- upload context to populate
 *     headers_in -- request headers
 *
 * Return value:
 *     NGX_OK on success
 *     NGX_ERROR if error has occured
 */
static ngx_int_t upload_parse_request_headers(ngx_http_upload_ctx_t *upload_ctx, ngx_http_headers_in_t *headers_in);

/*
 * upload_process_buf
 *
 * Process buffer with multipart stream starting from start and terminating
 * by end, operating on upload_ctx. The header information is accumulated in
 * This call can invoke one or more calls to start_upload_file, finish_upload_file,
 * abort_upload_file and flush_output_buffer routines.
 *
 * Returns value NGX_OK successful
 *               NGX_UPLOAD_MALFORMED stream is malformed
 *               NGX_UPLOAD_NOMEM insufficient memory 
 *               NGX_UPLOAD_IOERROR input-output error
 *               NGX_UPLOAD_SCRIPTERROR nginx script engine failed
 *               NGX_UPLOAD_TOOLARGE field body is too large
 */
static ngx_int_t upload_process_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end);
static ngx_int_t upload_process_raw_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end);

static ngx_command_t  ngx_http_upload_commands[] = { /* {{{ */
	{ ngx_string("mytest"),      /* 设定echo的handler */
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      &ngx_conf_set_echo,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Enables uploads for location and specifies location to pass modified request to  
     */
    { ngx_string("upload_pass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_upload_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Specifies base path of file store
     */
    { ngx_string("upload_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_path),
      NULL },

    /*
     * Specifies base path of state store
     */
    { ngx_string("upload_state_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, state_store_path),
      NULL },

    /*
     * Specifies the access mode for files in store
     */
    { ngx_string("upload_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_access),
      NULL },

    /*
     * Specifies the size of buffer, which will be used
     * to write data to disk
     */
    { ngx_string("upload_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, buffer_size),
      NULL },

    /*
     * Specifies the size of buffer, which will be used
     * for merging ranges into state file
     */
    { ngx_string("upload_merge_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, merge_buffer_size),
      NULL },

    /*
     * Specifies the size of buffer, which will be used
     * for returning range header
     */
    { ngx_string("upload_range_header_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, range_header_buffer_size),
      NULL },

    /*
     * Specifies the maximal length of the part header
     */
    { ngx_string("upload_max_part_header_len"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_header_len),
      NULL },

    /*
     * Specifies the maximal size of the file to be uploaded
     */
    { ngx_string("upload_max_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_file_size),
      NULL },

    /*
     * Specifies the maximal length of output body
     */
    { ngx_string("upload_max_output_body_len"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_output_body_len),
      NULL },

    /*
     * Specifies the field to set in altered response body
     */
    { ngx_string("upload_set_form_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_upload_set_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, field_templates),
      NULL},

    /*
     * Specifies the field with aggregate parameters
     * to set in altered response body
     */
    { ngx_string("upload_aggregate_form_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_upload_set_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, aggregate_field_templates),
      NULL},

    /*
     * Specifies the field to pass to backend
     */
    { ngx_string("upload_pass_form_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_upload_pass_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    /*
     * Specifies http statuses upon reception of
     * which cleanup of uploaded files will be initiated
     */
    { ngx_string("upload_cleanup"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_1MORE,
      ngx_http_upload_cleanup,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

     /*
      * Specifies the whether or not to forward query args
      * to the upload_pass redirect location
      */
     { ngx_string("upload_pass_args"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                         |NGX_CONF_FLAG,
       ngx_conf_set_flag_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_upload_loc_conf_t, forward_args),
       NULL },

     /*
      * Specifies request body reception rate limit
      */
    { ngx_string("upload_limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, limit_rate),
      NULL },

     /*
      * Specifies whether array brackets in file field names must be dropped
      */
     { ngx_string("upload_tame_arrays"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                         |NGX_CONF_FLAG,
       ngx_conf_set_flag_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_upload_loc_conf_t, tame_arrays),
       NULL },

     /*
      * Specifies whether resumable uploads are allowed
      */
     { ngx_string("upload_resumable"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_HTTP_LIF_CONF
                         |NGX_CONF_FLAG,
       ngx_conf_set_flag_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_upload_loc_conf_t, resumable_uploads),
       NULL },

      ngx_null_command
}; /* }}} */

ngx_http_module_t  ngx_http_upload_module_ctx = { /* {{{ */
    ngx_http_upload_add_variables,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_upload_create_loc_conf,       /* create location configuration */
    ngx_http_upload_merge_loc_conf         /* merge location configuration */
}; /* }}} */

ngx_module_t  ngx_http_upload_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_http_upload_module_ctx,           /* module context */
    ngx_http_upload_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
}; /* }}} */

static ngx_http_variable_t  ngx_http_upload_variables[] = { /* {{{ */

    { ngx_string("upload_field_name"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, field_name),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_content_type"),
      ngx_http_upload_variable_set,
      ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, content_type),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_name"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, file_name),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_number"), NULL, ngx_http_upload_uint_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, ordinal),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_tmp_path"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, output_file.name),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_content_range"),
      ngx_http_upload_content_range_variable_set,
      ngx_http_upload_content_range_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, content_range_n),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; /* }}} */

static ngx_http_variable_t  ngx_http_upload_aggregate_variables[] = { /* {{{ */

    { ngx_string("upload_file_md5"), NULL, ngx_http_upload_md5_variable,
      (uintptr_t) "0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_md5_uc"), NULL, ngx_http_upload_md5_variable,
      (uintptr_t) "0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha1"), NULL, ngx_http_upload_sha1_variable,
      (uintptr_t) "0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha1_uc"), NULL, ngx_http_upload_sha1_variable,
      (uintptr_t) "0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_crc32"), NULL, ngx_http_upload_crc32_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, crc32),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_size"), NULL, ngx_http_upload_file_size_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, output_file.offset),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; /* }}} */

static ngx_str_t  ngx_http_upload_empty_field_value = ngx_null_string;

static ngx_str_t  ngx_upload_field_part1 = { /* {{{ */
    sizeof(CRLF CONTENT_DISPOSITION_STRING " form-data; name=\"") - 1,
    (u_char*)CRLF CONTENT_DISPOSITION_STRING " form-data; name=\""
}; /* }}} */

static ngx_str_t  ngx_upload_field_part2 = { /* {{{ */
    sizeof("\"" CRLF CRLF) - 1,
    (u_char*)"\"" CRLF CRLF
}; /* }}} */
/**
static ngx_int_t ngx_http_upload_handler(ngx_http_request_t *r)
{
    ngx_http_upload_loc_conf_t  *ulcf;
    ngx_http_upload_ctx_t     *u;
    ngx_int_t                 rc;
	ngx_http_upstream_t*    upstream;

    if (!(r->method & NGX_HTTP_POST))
        return NGX_HTTP_NOT_ALLOWED;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if (u == NULL) {
        u = ngx_pcalloc(r->pool, sizeof(ngx_http_upload_ctx_t));
        if (u == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, u, ngx_http_upload_module);
    }

	//jin.shang
    if (ngx_http_upstream_create(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	upstream = r->upstream;
	r->subrequest_in_memory = 1;//希望不接受upstream响应体
	//upstream->output.tag = (ngx_buf_tag_t) &ngx_http_upload_module;
	ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);
    upstream->conf = &ulcf->upstream;
	upstream->buffering = ulcf->upstream.buffering;
	//upstream->buffering = 1;
	upstream->create_request = ngx_http_upload_create_request;
	upstream->process_header = ngx_http_upload_process_header;
	upstream->finalize_request = ngx_http_upload_finalize_request;


    if(ulcf->md5) {
        if(u->md5_ctx == NULL) {
            u->md5_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_md5_ctx_t));
            if (u->md5_ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->md5_ctx = NULL;

    if(ulcf->sha1) {
        if(u->sha1_ctx == NULL) {
            u->sha1_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_sha1_ctx_t));
            if (u->sha1_ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->sha1_ctx = NULL;

    u->calculate_crc32 = ulcf->crc32;

    u->request = r;
    u->log = r->connection->log;
    u->chain = u->last = u->checkpoint = NULL;
    u->output_body_len = 0;

    u->prevent_output = 0;
    u->no_content = 1;
    u->limit_rate = ulcf->limit_rate;
    u->received = 0;
    u->ordinal = 0;

    upload_init_ctx(u);

    rc = upload_parse_request_headers(u, &r->headers_in);

    if(rc != NGX_OK) {
        upload_shutdown_ctx(u);
        return rc;
    }

    if(upload_start(u, ulcf) != NGX_OK) {
		//ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xoxoxoxoxoxo 1 2 3 4 5 6 ");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

    rc = ngx_http_read_upload_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args is : %V",  &r->args);
u_char *start = r->args.data;
u_char * p = start;
u_char * b = ngx_pcalloc(r->pool, 20);
int i = 0;
while(i<r->args.len) {
	if(*p == '&') {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args len : %d",  p-start);
		ngx_memcpy(b, start, p-start);
		ngx_http_upload_parse_args(u, b, p-start);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args b : %s",  b);
		p++;
		start = p;
		i++;
	}
	p++;
	i++;

}
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args len : %d",  p-start);
		ngx_memcpy(b, start, p-start);
		ngx_http_upload_parse_args(u, b, p-start);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args b : %s",  b);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] uri is : %V",  &r->uri);
	//jin.shang
 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xoxoxoxoxoxo upstream init start");
	//ngx_http_upstream_init(r);
 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xoxoxoxoxoxo upstream init end");
    return NGX_DONE;
}
**/

static ngx_int_t ngx_http_upload_body_handler(ngx_http_request_t *r) { /* {{{ */
    ngx_http_upload_loc_conf_t  *ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_upload_module);
    ngx_http_upload_ctx_t       *ctx = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    ngx_str_t                   args;
    ngx_uint_t                  flags;
    ngx_int_t                   rc;
    ngx_str_t                   uri;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl, out;
    ngx_str_t                   dummy = ngx_string("<ngx_upload_module_dummy>");
    ngx_table_elt_t             *h;

    if(ctx->prevent_output) {
        r->headers_out.status = NGX_HTTP_CREATED;

        /*
         * Add range header and body
         */
        if(ctx->range_header_buffer_pos != ctx->range_header_buffer) {
            h = (ngx_table_elt_t*)ngx_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            h->hash = 1;
            h->key.len = sizeof("Range") - 1;
            h->key.data = (u_char *) "Range";
            h->value.len = ctx->range_header_buffer_pos - ctx->range_header_buffer;
            h->value.data = ctx->range_header_buffer;

            b = (ngx_buf_t*)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
            if (b == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->headers_out.content_length_n = h->value.len;

            r->allow_ranges = 0;

            rc = ngx_http_send_header(r);

            if(rc == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if(rc > NGX_OK) {
                return rc;
            }

            b->in_file = 0;
            b->memory = 1;
            b->last_buf = b->last_in_chain = b->flush = 1;

            b->start = b->pos = ctx->range_header_buffer;
            b->last = ctx->range_header_buffer_pos;
            b->end = ctx->range_header_buffer_end;

            out.buf = b;
            out.next = NULL;

            ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
        }
        else {
            r->header_only = 1;
            r->headers_out.content_length_n = 0;

            ngx_http_finalize_request(r, ngx_http_send_header(r));
        }

        return NGX_OK;
    }

    if(ulcf->max_output_body_len != 0) {
        if(ctx->output_body_len + ctx->boundary.len + 4 > ulcf->max_output_body_len)
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    if(ctx->no_content) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error a");
        rc = ngx_http_upload_append_field(ctx, &dummy, &ngx_http_upload_empty_field_value);

		if(rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /*
     * Append final boundary
     */
    b = ngx_create_temp_buf(r->pool, ctx->boundary.len + 4);

    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last_in_chain = 1;
    b->last_buf = 1;

    cl->buf = b;
    cl->next = NULL;
    
    if(ctx->chain == NULL) {
        ctx->chain = cl;
        ctx->last = cl;
    }else{
        ctx->last->next = cl;
        ctx->last = cl;
    }

    b->last = ngx_cpymem(b->last, ctx->boundary.data, ctx->boundary.len);

    *b->last++ = '-';
    *b->last++ = '-';
    *b->last++ = CR;
    *b->last++ = LF;

    if (ulcf->url_cv) {
        /* complex value */
        if (ngx_http_complex_value(r, ulcf->url_cv, &uri) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (uri.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "empty \"upload_pass\" (was: \"%V\")",
                          &ulcf->url_cv->value);

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error d");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        /* simple value */
        uri = ulcf->url;
    }

    if (ulcf->forward_args) {
      args = r->args; /* forward the query args */
    }
    else {
      args.len = 0;
      args.data = NULL;
    }

    flags = 0;

    //if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
	//	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error e: %V", &uri);
      //  return NGX_HTTP_INTERNAL_SERVER_ERROR;
    //}

    r->request_body->bufs = ctx->chain;

    // Recalculate content length
    r->headers_in.content_length_n = 0;

    for(cl = ctx->chain ; cl ; cl = cl->next)
        r->headers_in.content_length_n += (cl->buf->last - cl->buf->pos);

    r->headers_in.content_length->value.data = (u_char*)ngx_palloc(r->pool, NGX_OFF_T_LEN);

    if (r->headers_in.content_length->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_in.content_length->value.len =
        ngx_sprintf(r->headers_in.content_length->value.data, "%O", r->headers_in.content_length_n)
            - r->headers_in.content_length->value.data;

	  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error -- maincount: %d", r->main->count);
    r->main->count--;

    if(uri.len != 0 && uri.data[0] == '/') {
        //rc = ngx_http_internal_redirect(r, &uri, &args);
    }
    else{
        //rc = ngx_http_named_location(r, &uri);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return rc;
} /* }}} */

static ngx_int_t ngx_http_upload_start_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    ngx_http_request_t        *r = u->request;
    ngx_http_upload_loc_conf_t  *ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    ngx_file_t  *file = &u->output_file;
    ngx_path_t  *path = ulcf->store_path;
    uint32_t    n;
    ngx_uint_t  i;
    ngx_int_t   rc;
    ngx_err_t   err;
    ngx_http_upload_field_template_t    *t;
    ngx_http_upload_field_filter_t    *f;
    ngx_str_t   field_name, field_value;
    ngx_uint_t  pass_field;
    ngx_upload_cleanup_t  *ucln;

    if(u->is_file) {
        u->ordinal++;

        u->cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_upload_cleanup_t));

        if(u->cln == NULL)
            return NGX_UPLOAD_NOMEM;

        file->name.len = path->name.len + 1 + path->len + (u->session_id.len != 0 ? u->session_id.len : 10);

        file->name.data = (u_char*)ngx_palloc(u->request->pool, file->name.len + 1);

        if(file->name.data == NULL)
            return NGX_UPLOAD_NOMEM;

        ngx_memcpy(file->name.data, path->name.data, path->name.len);

        file->log = r->connection->log;

		//此步不会执行，因为请求头中不存在session
        if(u->session_id.len != 0) {
            (void) ngx_sprintf(file->name.data + path->name.len + 1 + path->len,
                               "%V%Z", &u->session_id);

            ngx_create_hashed_filename(path, file->name.data, file->name.len);

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                           "hashed path: %s", file->name.data);

            if(u->partial_content) {
                if(u->merge_buffer == NULL) {
                    u->merge_buffer = (u_char*)ngx_palloc(r->pool, ulcf->merge_buffer_size);

                    if(u->merge_buffer == NULL)
                        return NGX_UPLOAD_NOMEM;
                }

                u->state_file.name.len = file->name.len + sizeof(".state") - 1;
                u->state_file.name.data = (u_char*)ngx_palloc(u->request->pool, u->state_file.name.len + 1);

                if(u->state_file.name.data == NULL)
                    return NGX_UPLOAD_NOMEM;

                ngx_memcpy(u->state_file.name.data, file->name.data, file->name.len);

                /*
                 * NOTE: we add terminating zero for system calls
                 */
                ngx_memcpy(u->state_file.name.data + file->name.len, ".state", sizeof(".state") - 1 + 1);

                ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                               "hashed path of state file: %s", u->state_file.name.data);
            }

            file->fd = ngx_open_file(file->name.data, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN, ulcf->store_access);

            if (file->fd == NGX_INVALID_FILE) {
                err = ngx_errno;

                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "failed to create output file \"%V\" for \"%V\"", &file->name, &u->file_name);
                return NGX_UPLOAD_IOERROR;
            }

            file->offset = u->content_range_n.start;
        }
        else{
			//会执行此分支
			//上传几张，就会执行几次，在这里主要是创建文件
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, file->log, 0, "error bbbbbbbbbbbbbbbbbbbbbb create file");
/**            for(;;) {

                n = (uint32_t) ngx_next_temp_number(0);

                (void) ngx_sprintf(file->name.data + path->name.len + 1 + path->len,
                                   "%010uD%Z", n);

                ngx_create_hashed_filename(path, file->name.data, file->name.len);

               // ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0, "error bbbbbbbbbbbbbbbbbbbbbb hashed path: %s", file->name.data);

                file->fd = ngx_open_tempfile(file->name.data, 1, ulcf->store_access);

                if (file->fd != NGX_INVALID_FILE) {
                    file->offset = 0;
                    break;
                }

                err = ngx_errno;

                if (err == NGX_EEXIST) {
                    n = (uint32_t) ngx_next_temp_number(1);
                    continue;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "failed to create output file \"%V\" for \"%V\"", &file->name, &u->file_name);
                return NGX_UPLOAD_IOERROR;
            }**/
        }

        u->cln->handler = ngx_upload_cleanup_handler;

        ucln = (ngx_upload_cleanup_t*)u->cln->data;
        ucln->fd = file->fd;
        ucln->filename = file->name.data;
        ucln->log = r->connection->log;
        ucln->headers_out = &r->headers_out;
        ucln->cleanup_statuses = ulcf->cleanup_statuses;
        ucln->aborted = 0;
		//如果设定了upload_set_form_field命令，则会执行这步
        if(ulcf->field_templates) {

            if(ulcf->tame_arrays && u->field_name.len > 2 &&
                u->field_name.data[u->field_name.len - 1] == ']' &&
                u->field_name.data[u->field_name.len - 2] == '[')
            {
                u->field_name.len -= 2;
            }

            t = (ngx_http_upload_field_template_t*)ulcf->field_templates->elts;
            for (i = 0; i < ulcf->field_templates->nelts; i++) {

                if (t[i].field_lengths == NULL) {
                    field_name = t[i].value.key;
                }else{
                    if (ngx_http_script_run(r, &field_name, t[i].field_lengths->elts, 0,
                        t[i].field_values->elts) == NULL)
                    {
                        rc = NGX_UPLOAD_SCRIPTERROR;
                        goto cleanup_file;
                    }
                }

                if (t[i].value_lengths == NULL) {
                    field_value = t[i].value.value;
                }else{
                    if (ngx_http_script_run(r, &field_value, t[i].value_lengths->elts, 0,
                        t[i].value_values->elts) == NULL)
                    {
                        rc = NGX_UPLOAD_SCRIPTERROR;
                        goto cleanup_file;
                    }
                }
ngx_log_debug0(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "error b");
                rc = ngx_http_upload_append_field(u, &field_name, &field_value);

                if(rc != NGX_OK)
                    goto cleanup_file;
            }
        }

        if(u->md5_ctx != NULL)
            MD5Init(&u->md5_ctx->md5);

        if(u->sha1_ctx != NULL)
            SHA1_Init(&u->sha1_ctx->sha1);

        if(u->calculate_crc32)
            ngx_crc32_init(u->crc32);

        if(u->partial_content) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
                , "started uploading part %O-%O/%O of file \"%V\" to \"%V\" (field \"%V\", content type \"%V\")"
                , u->content_range_n.start
                , u->content_range_n.end
                , u->content_range_n.total
                , &u->file_name
                , &u->output_file.name
                , &u->field_name
                , &u->content_type
                );
        }
        else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
                , "started uploading file \"%V\" to \"%V\" (field \"%V\", content type \"%V\")"
                , &u->file_name
                , &u->output_file.name
                , &u->field_name
                , &u->content_type
                );
        }
    }else{
        pass_field = 0;

        if(ulcf->field_filters) {
            f = (ngx_http_upload_field_filter_t*)ulcf->field_filters->elts;
            for (i = 0; i < ulcf->field_filters->nelts; i++) {
#if (NGX_PCRE)
                rc = ngx_regex_exec(f[i].regex, &u->field_name, NULL, 0);

                if (rc != NGX_REGEX_NO_MATCHED && rc < 0) {
                    return NGX_UPLOAD_SCRIPTERROR;
                }

                /*
                 * If at least one filter succeeds, we pass the field
                 */
                if(rc == 0)
                    pass_field = 1;
#else
                if(ngx_strncmp(f[i].text.data, u->field_name.data, u->field_name.len) == 0)
                    pass_field = 1;
#endif
            }
        }

        if(pass_field && u->field_name.len > 0) { 
            /*
             * Here we do a small hack: the content of a non-file field
             * is not known until ngx_http_upload_flush_output_buffer
             * is called. We pass empty field value to simplify things.
             */
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "error c");
            rc = ngx_http_upload_append_field(u, &u->field_name, &ngx_http_upload_empty_field_value);

            if(rc != NGX_OK)
                return rc;
        }else
            u->discard_data = 1;
    }

    return NGX_OK;

cleanup_file:
    return rc;
} /* }}} */
//此方法会在将所有数据存到文件后被调用，此方法最简单的逻辑就是关闭文件
static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    ngx_http_upload_field_template_t    *af;
    ngx_str_t   aggregate_field_name, aggregate_field_value;
    ngx_http_request_t        *r = u->request;
    ngx_http_upload_loc_conf_t  *ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_upload_module);
    ngx_uint_t  i;
    ngx_int_t   rc;
    ngx_upload_cleanup_t  *ucln;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "error ooooooooooooooooooooooooo body len: %d", u->output_body_len);
	/**************************************
	 * jin.shang
	 *************************************/
	string image;
	//u_char *pic;
	u_char *tmp_pos;
	ngx_chain_t *cl;
	u->pic = (u_char*)ngx_pcalloc(u->request->pool, u->output_body_len);
	if(u->pic == NULL)
		return;
	tmp_pos = u->pic;
	if(u->chain == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "error u->chain is NULL");
		return;
	}
	for(cl=u->chain; cl; cl=cl->next) {
		ngx_memcpy(tmp_pos, cl->buf->pos, cl->buf->last - cl->buf->pos);
		tmp_pos += cl->buf->last - cl->buf->pos;
	}
	
	image.assign(reinterpret_cast<const char*>(u->pic), u->output_body_len);
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error pic size %d ", image.size());
	//if(images.empty())
		//ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error empty empty");

	images.push_back(image);

    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error push back %d ", (int)images.size());
	u->chain = u->last = NULL;
	u->output_body_len = 0;


    if(u->is_file) {
        ucln = (ngx_upload_cleanup_t*)u->cln->data;
        ucln->fd = -1;

        ngx_close_file(u->output_file.fd);

        if(u->md5_ctx)
            MD5Final(u->md5_ctx->md5_digest, &u->md5_ctx->md5);

        if(u->sha1_ctx)
            SHA1_Final(u->sha1_ctx->sha1_digest, &u->sha1_ctx->sha1);

        if(u->calculate_crc32)
            ngx_crc32_final(u->crc32);

		//该分支不会被执行
        if(u->partial_content) {
            if(u->output_file.offset != u->content_range_n.end + 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0
                    , "file offset at the end of a part %O does not match the end specified range %O-%O/%O"
                    , u->output_file.offset
                    , u->content_range_n.start
                    , u->content_range_n.end
                    , u->content_range_n.total
                    , u->output_file.name
                    );

                goto rollback;
            }

            rc = ngx_http_upload_merge_ranges(u, &u->content_range_n);

            if(rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0
                    , "error merging ranges"
                    );

                goto rollback;
            }

            if(rc == NGX_AGAIN) {
                /*
                 * If there are more parts to go, we do not produce any output
                 */
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
                    , "finished uploading part %O-%O/%O of a file \"%V\" to \"%V\""
                    , u->content_range_n.start
                    , u->content_range_n.end
                    , u->content_range_n.total
                    , &u->file_name
                    , &u->output_file.name
                    );

                u->prevent_output = 1;

                return;
            }

            if(ngx_delete_file(u->state_file.name.data) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to remove state file \"%V\"", &u->state_file.name);
            } else {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "removed state file \"%V\"", &u->state_file.name);
            }
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
            , "finished uploading file \"%V\" to \"%V\""
            , &u->file_name
            , &u->output_file.name
            );

		//此步不会执行
        if(ulcf->aggregate_field_templates) {
            af = (ngx_http_upload_field_template_t*)ulcf->aggregate_field_templates->elts;
            for (i = 0; i < ulcf->aggregate_field_templates->nelts; i++) {

                if (af[i].field_lengths == NULL) {
                    aggregate_field_name = af[i].value.key;
                }else{
                    if (ngx_http_script_run(r, &aggregate_field_name, af[i].field_lengths->elts, 0,
                        af[i].field_values->elts) == NULL)
                    {
                        goto rollback;
                    }
                }

                if (af[i].value_lengths == NULL) {
                    aggregate_field_value = af[i].value.value;
                }else{
                    if (ngx_http_script_run(r, &aggregate_field_value, af[i].value_lengths->elts, 0,
                        af[i].value_values->elts) == NULL)
                    {
                        goto rollback;
                    }
                }
                rc = ngx_http_upload_append_field(u, &aggregate_field_name, &aggregate_field_value);

                if(rc != NGX_OK)
                    goto rollback;
            }
        }
    }

    // Checkpoint current output chain state
    u->checkpoint = u->last;
    return;

rollback:
    ngx_http_upload_abort_handler(u);
} /* }}} */
//此方法也是关闭文件，但是比finish多了将chain置为null的操作
static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    ngx_upload_cleanup_t  *ucln;

    if(u->is_file) {
        /*
         * Upload of a part could be aborted due to temporary reasons, thus
         * next body part will be potentially processed successfuly.
         *
         * Therefore we don't postpone cleanup to the request finallization
         * in order to save additional resources, instead we mark existing
         * cleanup record as aborted.
         */
        ucln = (ngx_upload_cleanup_t*)u->cln->data;
        ucln->fd = -1;
        ucln->aborted = 1;

        ngx_close_file(u->output_file.fd);

        if(!u->partial_content) {
            if(ngx_delete_file(u->output_file.name.data) == NGX_FILE_ERROR) { 
                ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno
                    , "aborted uploading file \"%V\" to \"%V\", failed to remove destination file"
                    , &u->file_name
                    , &u->output_file.name);
            } else {
                ngx_log_error(NGX_LOG_ALERT, u->log, 0
                    , "aborted uploading file \"%V\" to \"%V\", dest file removed"
                    , &u->file_name
                    , &u->output_file.name);
            }
        }
    }

    // Rollback output chain to the previous consistant state
    if(u->checkpoint != NULL) {
        u->last = u->checkpoint;
        u->last->next = NULL;
    }else{
        u->chain = u->last = NULL;
        u->first_part = 1;
    }
} /* }}} */

static ngx_int_t ngx_http_upload_flush_output_buffer(ngx_http_upload_ctx_t *u, u_char *buf, size_t len) { /* {{{ */
    ngx_http_request_t             *r = u->request;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_upload_loc_conf_t     *ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_upload_module);
	//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "error ooooooooooooooooooooooooo: %d, %d", buf, len);
    if(!u->is_file) {
        if(u->partial_content) {
            if(u->output_file.offset > u->content_range_n.end)
                return NGX_OK;

            if(u->output_file.offset + (off_t)len > u->content_range_n.end + 1)
                len = u->content_range_n.end - u->output_file.offset + 1;
        }

        if(u->md5_ctx)
            MD5Update(&u->md5_ctx->md5, buf, len);

        if(u->sha1_ctx)
            SHA1_Update(&u->sha1_ctx->sha1, buf, len);

        if(u->calculate_crc32)
            ngx_crc32_update(&u->crc32, buf, len);

        if(ulcf->max_file_size != 0 && !u->partial_content) {
            if(u->output_file.offset + (off_t)len > ulcf->max_file_size)
                return NGX_UPLOAD_TOOLARGE;
        }

		//此步是真正的写文件，实际上调用的是pwrite
		
        if(ngx_write_file(&u->output_file, buf, len, u->output_file.offset) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                           "write to file \"%V\" failed", &u->output_file.name);
            return NGX_UPLOAD_IOERROR;
        }else
            return NGX_OK;
    }else{
		//如果读进来的包体不用文件存的话，就用u->chain存储，u->last指示最后一个buf
        if(ulcf->max_output_body_len != 0) {
            if (u->output_body_len + len > ulcf->max_output_body_len)
                return NGX_UPLOAD_TOOLARGE;
        }

	//ngx_log_debug2(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "error ooooooooooooooooooooooooo: bodylen:%d, len:%d", u->output_body_len, len);
        u->output_body_len += len;

        b = ngx_create_temp_buf(u->request->pool, len);

        if (b == NULL) {
            return NGX_ERROR;
        }

        cl = ngx_alloc_chain_link(u->request->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b->last_in_chain = 0;

        cl->buf = b;
        cl->next = NULL;

        b->last = ngx_cpymem(b->last, buf, len);

        if(u->chain == NULL) {
            u->chain = cl;
            u->last = cl;
        }else{
            u->last->next = cl;
            u->last = cl;
        }

        return NGX_OK;
    }
} /* }}} */

static void /* {{{ ngx_http_upload_append_str */
ngx_http_upload_append_str(ngx_http_upload_ctx_t *u, ngx_buf_t *b, ngx_chain_t *cl, ngx_str_t *s)
{
    b->start = b->pos = s->data;
    b->end = b->last = s->data + s->len;
    b->memory = 1;
    b->temporary = 1;
    b->in_file = 0;
    b->last_buf = 0;

    b->last_in_chain = 0;
    b->last_buf = 0;

    cl->buf = b;
    cl->next = NULL;

    if(u->chain == NULL) {
        u->chain = cl;
        u->last = cl;
    }else{
        u->last->next = cl;
        u->last = cl;
    }

    u->output_body_len += s->len;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_append_field */
ngx_http_upload_append_field(ngx_http_upload_ctx_t *u, ngx_str_t *name, ngx_str_t *value)
{
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "error appppppppppppppppend: %V, %V", name, value);
    ngx_http_upload_loc_conf_t     *ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);
    ngx_str_t   boundary = { u->first_part ? u->boundary.len - 2 : u->boundary.len,
         u->first_part ? u->boundary.data + 2 : u->boundary.data };

    ngx_buf_t *b;
    ngx_chain_t *cl;

    if(name->len > 0) {
        if(ulcf->max_output_body_len != 0) {
            if(u->output_body_len + boundary.len + ngx_upload_field_part1.len + name->len
               + ngx_upload_field_part2.len + value->len > ulcf->max_output_body_len) {
                return NGX_UPLOAD_TOOLARGE;
			}
        }

        b = (ngx_buf_t*)ngx_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(ngx_buf_t) : 4 * sizeof(ngx_buf_t));

        if (b == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        cl = (ngx_chain_t*)ngx_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(ngx_chain_t) : 4 * sizeof(ngx_chain_t));

        if (cl == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        ngx_http_upload_append_str(u, b, cl, &boundary);

        ngx_http_upload_append_str(u, b + 1, cl + 1, &ngx_upload_field_part1);

        ngx_http_upload_append_str(u, b + 2, cl + 2, name);

        ngx_http_upload_append_str(u, b + 3, cl + 3, &ngx_upload_field_part2);

        if(value->len > 0)
            ngx_http_upload_append_str(u, b + 4, cl + 4, value);

        u->output_body_len += boundary.len + ngx_upload_field_part1.len + name->len
            + ngx_upload_field_part2.len + value->len;

        u->first_part = 0;

        u->no_content = 0;
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t ngx_http_upload_add_range(ngx_http_upload_merger_state_t *ms, ngx_http_upload_range_t *range_n) {
    ms->out_buf->last = ngx_sprintf(ms->out_buf->last, "%O-%O/%O\x0a",
        range_n->start,
        range_n->end,
        range_n->total);

    if(*ms->range_header_buffer_pos < ms->range_header_buffer_end) {
        *ms->range_header_buffer_pos = ngx_sprintf(*ms->range_header_buffer_pos,
            ms->first_range ? "%O-%O/%O" : ",%O-%O/%O",
            range_n->start,
            range_n->end,
            range_n->total);

        ms->first_range = 0;
    }

    return NGX_OK;
}

static ngx_int_t /* {{{ ngx_http_upload_buf_merge_range */
ngx_http_upload_buf_merge_range(ngx_http_upload_merger_state_t *ms, ngx_http_upload_range_t *range_n) {
    u_char *p, c;
    off_t                  *field;

    p = ms->in_buf->pos;

    field = ms->parser_state;

    do{
        *field = 0;

        while(p != ms->in_buf->last) {

            c = *p++;

            if(c >= '0' && c <= '9') {
                (*field) = (*field) * 10 + (c - '0');
            }
            else if(c == '-') {
                if(field != &ms->current_range_n.start) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ms->log, 0,
                                   "unexpected - while parsing range");
                    return NGX_ERROR;
                }

                field = &ms->current_range_n.end;
                break;
            }
            else if(c == '/') {
                if(field != &ms->current_range_n.end) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ms->log, 0,
                                   "unexpected / while parsing range");
                    return NGX_ERROR;
                }

                field = &ms->current_range_n.total;
                break;
            }
            else if(c == LF) {
                if(field != &ms->current_range_n.total) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ms->log, 0,
                                   "unexpected end of line while parsing range");
                    return NGX_ERROR;
                }

                if(ms->current_range_n.start >= ms->current_range_n.end || ms->current_range_n.start >= ms->current_range_n.total
                    || ms->current_range_n.end > ms->current_range_n.total)
                {
                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, ms->log, 0,
                                   "inconsistent bounds while parsing range: %O-%O/%O",
                                   ms->current_range_n.start,
                                   ms->current_range_n.end,
                                   ms->current_range_n.total);
                    return NGX_ERROR;
                }

                if(ms->current_range_n.total != range_n->total) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ms->log, 0,
                                   "total number of bytes mismatch while parsing range");
                    return NGX_ERROR;
                } 

                field = &ms->current_range_n.start;

                if(ms->current_range_n.end + 1 < range_n->start) {
                    /*
                     * Current range is entirely below the new one,
                     * output current one and seek next
                     */
                    if(ngx_http_upload_add_range(ms, &ms->current_range_n) != NGX_OK) {
                        return NGX_ERROR;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, ms->log, 0,
                                   "< %O-%O/%O", ms->current_range_n.start,
                                   ms->current_range_n.end, ms->current_range_n.total);
                    break;
                }

                if(ms->current_range_n.start > range_n->end + 1) {
                    /*
                     * Current range is entirely above the new one,
                     * insert new range
                     */
                    if(!ms->found_lower_bound) {
                        if(ngx_http_upload_add_range(ms, range_n) != NGX_OK) {
                            return NGX_ERROR;
                        }
                    }

                    if(ngx_http_upload_add_range(ms, &ms->current_range_n) != NGX_OK) {
                        return NGX_ERROR;
                    }

                    ngx_log_debug6(NGX_LOG_DEBUG_CORE, ms->log, 0,
                                   "> %O-%O/%O %O-%O/%O",
                                   range_n->start,
                                   range_n->end,
                                   range_n->total,
                                   ms->current_range_n.start,
                                   ms->current_range_n.end,
                                   ms->current_range_n.total);

                    ms->found_lower_bound = 1;
                    break;
                }

                /*
                 * Extend range to be merged with the current range
                 */
                range_n->start = range_n->start < ms->current_range_n.start ? range_n->start : ms->current_range_n.start;
                range_n->end = range_n->end > ms->current_range_n.end ? range_n->end : ms->current_range_n.end;
                break;
            }
            else {
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, ms->log, 0,
                               "unexpected character %c", *p);
                return NGX_ERROR;
            }
        }
    }while(p != ms->in_buf->last);

    if(ms->in_buf->last_buf) {
        if(field != &ms->current_range_n.start) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ms->log, 0,
                           "unexpected end of file while merging ranges");
            return NGX_ERROR;
        }

        if(!ms->found_lower_bound) {
            if(ngx_http_upload_add_range(ms, range_n) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ms->log, 0,
                           "a %O-%O/%O",
                           range_n->start,
                           range_n->end,
                           range_n->total);

            ms->complete_ranges = (range_n->start == 0) && (range_n->end == range_n->total - 1) ? 1 : 0;

            ms->found_lower_bound = 1;
        }
    }

    ms->parser_state = field;

    return NGX_OK;
} /* }}} */

//该函数不会被执行
static ngx_int_t /* {{{ ngx_http_upload_merge_ranges */
ngx_http_upload_merge_ranges(ngx_http_upload_ctx_t *u, ngx_http_upload_range_t *range_n) {
    ngx_file_t  *state_file = &u->state_file;
    ngx_http_upload_merger_state_t ms;
    off_t        remaining;
    ssize_t      rc;
    int          result;
    ngx_buf_t    in_buf;
    ngx_buf_t    out_buf;
    ngx_http_upload_loc_conf_t  *ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);
    ngx_http_upload_range_t  range_to_merge_n;
    

    state_file->fd = ngx_open_file(state_file->name.data, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN, ulcf->store_access);

    if (state_file->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno,
                      "failed to create or open state file \"%V\"", &state_file->name);
        return NGX_ERROR;
    }

    ngx_lock_fd(state_file->fd);

    ngx_fd_info(state_file->fd, &state_file->info);

    state_file->offset = 0;
    state_file->log = u->log;

    ms.in_buf = &in_buf;
    ms.out_buf = &out_buf;
    ms.parser_state = &ms.current_range_n.start;
    ms.log = u->log;

    ms.found_lower_bound = 0;
    ms.complete_ranges = 0;
    ms.first_range = 1;

    ms.range_header_buffer = u->range_header_buffer;
    ms.range_header_buffer_pos = &u->range_header_buffer_pos;
    ms.range_header_buffer_end = u->range_header_buffer_end;

    range_to_merge_n = *range_n;

    out_buf.start = out_buf.pos = out_buf.last = u->merge_buffer;
    out_buf.end = u->merge_buffer + (ulcf->merge_buffer_size >> 1) + NGX_OFF_T_LEN*3 + 2 + 1;
    out_buf.file_pos = 0;

    in_buf.start = in_buf.pos = in_buf.last = out_buf.end;
    in_buf.end = u->merge_buffer + ulcf->merge_buffer_size;

    do {
        in_buf.file_pos = state_file->offset;
        in_buf.pos = in_buf.last = in_buf.start;

        if(state_file->offset < state_file->info.st_size) {
            remaining = state_file->info.st_size - state_file->offset > in_buf.end - in_buf.start
                ? in_buf.end - in_buf.start : state_file->info.st_size - state_file->offset;

            rc = ngx_read_file(state_file, in_buf.pos, remaining, state_file->offset);

            if(rc < 0 || rc != remaining) {
                goto failed;
            }

            in_buf.last = in_buf.pos + rc;
        }

        in_buf.last_buf = state_file->offset == state_file->info.st_size ? 1 : 0;

        if(out_buf.pos != out_buf.last) {
            rc = ngx_write_file(state_file, out_buf.pos, out_buf.last - out_buf.pos, out_buf.file_pos);

            if(rc < 0 || rc != out_buf.last - out_buf.pos) {
                goto failed;
            }

            out_buf.file_pos += out_buf.last - out_buf.pos;
        }

        out_buf.pos = out_buf.last = out_buf.start;

        if(ngx_http_upload_buf_merge_range(&ms, &range_to_merge_n) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, u->log, 0,
                          "state file \"%V\" is corrupt", &state_file->name);
            rc = NGX_ERROR;
            goto failed;
        }
    } while(state_file->offset < state_file->info.st_size);

    if(out_buf.pos != out_buf.last) {
        rc = ngx_write_file(state_file, out_buf.pos, out_buf.last - out_buf.pos, out_buf.file_pos);

        if(rc < 0 || rc != out_buf.last - out_buf.pos) {
            goto failed;
        }

        out_buf.file_pos += out_buf.last - out_buf.pos;
    }

    if(out_buf.file_pos < state_file->info.st_size) {
        result = ftruncate(state_file->fd, out_buf.file_pos);
    }

    rc = ms.complete_ranges ? NGX_OK : NGX_AGAIN;

failed:
    ngx_unlock_fd(state_file->fd);

    ngx_close_file(state_file->fd);

    return rc;
} /* }}} */

static void * /* {{{ ngx_http_upload_create_loc_conf */
ngx_http_upload_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upload_loc_conf_t  *conf;

    conf = (ngx_http_upload_loc_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_upload_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->store_access = NGX_CONF_UNSET_UINT;
    conf->forward_args = NGX_CONF_UNSET;
    conf->tame_arrays = NGX_CONF_UNSET;
    conf->resumable_uploads = NGX_CONF_UNSET;

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->merge_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->range_header_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->max_header_len = NGX_CONF_UNSET_SIZE;
    conf->max_output_body_len = NGX_CONF_UNSET_SIZE;
    conf->max_file_size = NGX_CONF_UNSET;
    conf->limit_rate = NGX_CONF_UNSET_SIZE;


	//jin.shang
	conf->upstream.connect_timeout = 60000;
	conf->upstream.send_timeout = 60000;
	conf->upstream.read_timeout = 60000;

 	conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 8;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
	conf->upstream.buffer_size = ngx_pagesize;
	//conf->upstream.buffer_size = 32768;



    /*
     * conf->field_templates,
     * conf->aggregate_field_templates,
     * and conf->field_filters are
     * zeroed by ngx_pcalloc
     */

    return conf;
} /* }}} */

static char * /* {{{ ngx_http_upload_merge_loc_conf */
ngx_http_upload_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upload_loc_conf_t  *prev = (ngx_http_upload_loc_conf_t*)parent;
    ngx_http_upload_loc_conf_t  *conf = (ngx_http_upload_loc_conf_t*)child;

	//jin.shang
	ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
            prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
            prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
            prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
            prev->upstream.buffer_size,
            (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
            prev->upstream.next_upstream,
            (NGX_CONF_BITMASK_SET
             |NGX_HTTP_UPSTREAM_FT_ERROR
             |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
            |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

	//ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t) ngx_pagesize);


    if ((conf->url.len == 0) && (conf->url_cv == NULL)) {
        conf->url = prev->url;
        conf->url_cv = prev->url_cv;
    }

    if(conf->url.len != 0) {
#if defined nginx_version && nginx_version >= 7052
        ngx_conf_merge_path_value(cf,
                                  &conf->store_path,
                                  prev->store_path,
                                  &ngx_http_upload_temp_path);

        ngx_conf_merge_path_value(cf,
                                  &conf->state_store_path,
                                  prev->state_store_path,
                                  &ngx_http_upload_temp_path);
#else
        ngx_conf_merge_path_value(conf->store_path,
                                  prev->store_path,
                                  NGX_HTTP_PROXY_TEMP_PATH, 1, 2, 0,
                                  ngx_garbage_collector_temp_handler, cf);

        ngx_conf_merge_path_value(conf->state_store_path,
                                  prev->state_store_path,
                                  NGX_HTTP_PROXY_TEMP_PATH, 1, 2, 0,
                                  ngx_garbage_collector_temp_handler, cf);
#endif
    }

    ngx_conf_merge_uint_value(conf->store_access,
                              prev->store_access, 0600);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_size_value(conf->merge_buffer_size,
                              prev->merge_buffer_size,
                              (size_t) ngx_pagesize >> 1);

    ngx_conf_merge_size_value(conf->range_header_buffer_size,
                              prev->range_header_buffer_size,
                              (size_t) 256);

    ngx_conf_merge_size_value(conf->max_header_len,
                              prev->max_header_len,
                              (size_t) 512);

    ngx_conf_merge_size_value(conf->max_output_body_len,
                              prev->max_output_body_len,
                              (size_t) 100 * 1024);

    ngx_conf_merge_off_value(conf->max_file_size,
                             prev->max_file_size,
                             0);

    ngx_conf_merge_size_value(conf->limit_rate, prev->limit_rate, 0);

    if(conf->forward_args == NGX_CONF_UNSET) {
        conf->forward_args = (prev->forward_args != NGX_CONF_UNSET) ?
            prev->forward_args : 0;
    }

    if(conf->tame_arrays == NGX_CONF_UNSET) {
        conf->tame_arrays = (prev->tame_arrays != NGX_CONF_UNSET) ?
            prev->tame_arrays : 0;
    }

    if(conf->resumable_uploads == NGX_CONF_UNSET) {
        conf->resumable_uploads = (prev->resumable_uploads != NGX_CONF_UNSET) ?
            prev->resumable_uploads : 0;
    }

    if(conf->field_templates == NULL) {
        conf->field_templates = prev->field_templates;
    }

    if(conf->aggregate_field_templates == NULL) {
        conf->aggregate_field_templates = prev->aggregate_field_templates;

        if(prev->md5) {
            conf->md5 = prev->md5;
        }

        if(prev->sha1) {
            conf->sha1 = prev->sha1;
        }

        if(prev->crc32) {
            conf->crc32 = prev->crc32;
        }
    }

    if(conf->field_filters == NULL) {
        conf->field_filters = prev->field_filters;
    }

    if(conf->cleanup_statuses == NULL) {
        conf->cleanup_statuses = prev->cleanup_statuses;
    }

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_add_variables */
ngx_http_upload_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_upload_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    for (v = ngx_http_upload_aggregate_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_upload_variable_set */
ngx_http_upload_variable_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  *s;
    ngx_http_upload_ctx_t  *u;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    s = (ngx_str_t *) ((char *) u + data);

    s->len = v->len;
    s->data = v->data;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_variable */
ngx_http_upload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    ngx_str_t              *value;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (ngx_str_t *) ((char *) u + data);

    v->data = value->data;
    v->len = value->len;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_md5_variable */
ngx_http_upload_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_uint_t             i;
    ngx_http_upload_ctx_t  *u;
    u_char                 *c;
    u_char                 *hex_table;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if(u->md5_ctx == NULL || u->partial_content) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    hex_table = (u_char*)data;
    c = u->md5_ctx->md5_digest + MD5_DIGEST_LENGTH * 2;

    i = MD5_DIGEST_LENGTH;

    do{
        i--;
        *--c = hex_table[u->md5_ctx->md5_digest[i] & 0xf];
        *--c = hex_table[u->md5_ctx->md5_digest[i] >> 4];
    }while(i != 0);

    v->data = u->md5_ctx->md5_digest;
    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_sha1_variable */
ngx_http_upload_sha1_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_uint_t             i;
    ngx_http_upload_ctx_t  *u;
    u_char                 *c;
    u_char                 *hex_table;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if(u->sha1_ctx == NULL || u->partial_content) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    hex_table = (u_char*)data;
    c = u->sha1_ctx->sha1_digest + SHA_DIGEST_LENGTH * 2;

    i = SHA_DIGEST_LENGTH;

    do{
        i--;
        *--c = hex_table[u->sha1_ctx->sha1_digest[i] & 0xf];
        *--c = hex_table[u->sha1_ctx->sha1_digest[i] >> 4];
    }while(i != 0);

    v->data = u->sha1_ctx->sha1_digest;
    v->len = SHA_DIGEST_LENGTH * 2;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_crc32_variable */
ngx_http_upload_crc32_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    u_char                 *p;
    uint32_t               *value;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if(u->partial_content) {
        v->not_found = 1;
        return NGX_OK;
    }

    value = (uint32_t *) ((char *) u + data);

    p = (u_char*)ngx_palloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%08uxd", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_file_size_variable */
ngx_http_upload_file_size_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    u_char                 *p;
    off_t                  *value;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (off_t *) ((char *) u + data);

    p = (u_char*)ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_upload_content_range_variable_set */
ngx_http_upload_content_range_variable_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t   *u;
    ngx_str_t                val;
    ngx_http_upload_range_t *value;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (ngx_http_upload_range_t *) ((char *) u + data);

    val.len = v->len;
    val.data = v->data;

    if(ngx_http_upload_parse_range(&val, value) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid range \"%V\"", &val);
    }
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_content_range_variable */
ngx_http_upload_content_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    u_char                 *p;
    ngx_http_upload_range_t *value;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (ngx_http_upload_range_t *) ((char *) u + data);

    p = (u_char*)ngx_palloc(r->pool, sizeof("bytes ") - 1 + 3*NGX_OFF_T_LEN + 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = u->partial_content ?
        ngx_sprintf(p, "bytes %O-%O/%O", value->start, value->end, value->total) - p :
        ngx_sprintf(p, "bytes %O-%O/%O", (off_t)0, u->output_file.offset, u->output_file.offset) - p
        ;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_uint_variable */
ngx_http_upload_uint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    u_char                 *p;
    ngx_uint_t             *value;

    u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (ngx_uint_t *) ((char *) u + data);

    p = (u_char*)ngx_palloc(r->pool, sizeof("18446744073709551616") - 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_set_form_field */
ngx_http_upload_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   n, i;
    ngx_str_t                  *value;
    ngx_http_script_compile_t   sc;
    ngx_http_upload_field_template_t *h;
    ngx_array_t                 **field;
    ngx_http_variable_t         *v;
    u_char                      *match;
    ngx_http_upload_loc_conf_t  *ulcf = (ngx_http_upload_loc_conf_t*)conf;

    field = (ngx_array_t**) (((u_char*)conf) + cmd->offset);

    value = (ngx_str_t*)cf->args->elts;

    if (*field == NULL) {
        *field = ngx_array_create(cf->pool, 1,
                                  sizeof(ngx_http_upload_field_template_t));
        if (*field == NULL) {
            return (char*)NGX_CONF_ERROR;
        }
    }

    h = (ngx_http_upload_field_template_t*)ngx_array_push(*field);
    if (h == NULL) {
        return (char*)NGX_CONF_ERROR;
    }

    h->value.hash = 1;
    h->value.key = value[1];
    h->value.value = value[2];
    h->field_lengths = NULL;
    h->field_values = NULL;
    h->value_lengths = NULL;
    h->value_values = NULL;

    /*
     * Compile field name
     */
    n = ngx_http_script_variables_count(&value[1]);

    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &h->field_lengths;
        sc.values = &h->field_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return (char*)NGX_CONF_ERROR;
        }
    }

    /*
     * Compile field value
     */
    n = ngx_http_script_variables_count(&value[2]);

    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[2];
        sc.lengths = &h->value_lengths;
        sc.values = &h->value_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return (char*)NGX_CONF_ERROR;
        }
    }

    /*
     * Check for aggregate variables in script
     */
    for(i = 1;i <= 2;i++) {
        for (v = ngx_http_upload_aggregate_variables; v->name.len; v++) {
            match = ngx_strcasestrn(value[i].data, (char*)v->name.data, v->name.len - 1);

            /*
             * ngx_http_script_compile does check for final bracket earlier,
             * therefore we don't need to care about it, which simplifies things
             */
            if(match != NULL
                && ((match - value[i].data >= 1 && match[-1] == '$') 
                    || (match - value[i].data >= 2 && match[-2] == '$' && match[-1] == '{')))
            {
                if(cmd->offset != offsetof(ngx_http_upload_loc_conf_t, aggregate_field_templates)) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "variables upload_file_md5"
                                       ", upload_file_md5_uc"
                                       ", upload_file_sha1"
                                       ", upload_file_sha1_uc"
                                       ", upload_file_crc32"
                                       ", upload_content_range"
                                       " and upload_file_size"
                                       " could be specified only in upload_aggregate_form_field directive");
                    return (char*)NGX_CONF_ERROR;
                }

                if(v->get_handler == ngx_http_upload_md5_variable)
                    ulcf->md5 = 1;

                if(v->get_handler == ngx_http_upload_sha1_variable)
                    ulcf->sha1 = 1;

                if(v->get_handler == ngx_http_upload_crc32_variable)
                    ulcf->crc32 = 1;
            }
        }
    }

    return NGX_CONF_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_pass_form_field */
ngx_http_upload_pass_form_field(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf = (ngx_http_upload_loc_conf_t*)conf;

    ngx_str_t                  *value;
#if (NGX_PCRE)
#if defined nginx_version && nginx_version >= 8025
    ngx_regex_compile_t         rc;
    u_char                      errstr[NGX_MAX_CONF_ERRSTR];
#else
    ngx_int_t                   n;
    ngx_str_t                  err;
#endif
#endif
    ngx_http_upload_field_filter_t *f;

    value = (ngx_str_t*)cf->args->elts;

    if (ulcf->field_filters == NULL) {
        ulcf->field_filters = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_upload_field_filter_t));
        if (ulcf->field_filters == NULL) {
            return (char*)NGX_CONF_ERROR;
        }
    }

    f = (ngx_http_upload_field_filter_t*)ngx_array_push(ulcf->field_filters);
    if (f == NULL) {
        return (char*)NGX_CONF_ERROR;
    }

#if (NGX_PCRE)
#if defined nginx_version && nginx_version >= 8025
    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if(ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return (char*)NGX_CONF_ERROR;
    }

    f->regex = rc.regex;
    f->ncaptures = rc.captures;
#else
    f->regex = ngx_regex_compile(&value[1], 0, cf->pool, &err);

    if (f->regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
        return NGX_CONF_ERROR;
    }
    
    n = ngx_regex_capture_count(f->regex);

    if (n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_regex_capture_count_n " failed for "
                           "pattern \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    f->ncaptures = n;
#endif
#else
    f->text.len = value[1].len;
    f->text.data = value[1].data;
#endif

    return NGX_CONF_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_cleanup */
ngx_http_upload_cleanup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf = (ngx_http_upload_loc_conf_t*)conf;

    ngx_str_t                  *value;
    ngx_uint_t                 i;
    ngx_int_t                  status, lo, hi;
    uint16_t                   *s;

    value = (ngx_str_t*)cf->args->elts;

    if (ulcf->cleanup_statuses == NULL) {
        ulcf->cleanup_statuses = ngx_array_create(cf->pool, 1,
                                        sizeof(uint16_t));
        if (ulcf->cleanup_statuses == NULL) {
            return (char*)NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if(value[i].len > 4 && value[i].data[3] == '-') {
            lo = ngx_atoi(value[i].data, 3);

            if (lo == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid lower bound \"%V\"", &value[i]);
                return (char*)NGX_CONF_ERROR;
            }

            hi = ngx_atoi(value[i].data + 4, value[i].len - 4);

            if (hi == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid upper bound \"%V\"", &value[i]);
                return (char*)NGX_CONF_ERROR;
            }

            if (hi < lo) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "upper bound must be greater then lower bound in \"%V\"",
                                   &value[i]);
                return (char*)NGX_CONF_ERROR;
            }

        }else{
            status = ngx_atoi(value[i].data, value[i].len);

            if (status == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[i]);
                return (char*)NGX_CONF_ERROR;
            }

            hi = lo = status;
        }

        if (lo < 400 || hi > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "value(s) \"%V\" must be between 400 and 599",
                               &value[i]);
            return (char*)NGX_CONF_ERROR;
        }

        for(status = lo ; status <= hi; status++) {
            s = (uint16_t*)ngx_array_push(ulcf->cleanup_statuses);
            if (s == NULL) {
                return (char*)NGX_CONF_ERROR;
            }

            *s = status;
        }
    }


    return NGX_CONF_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_pass */
ngx_http_upload_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t          *clcf;
    ngx_http_upload_loc_conf_t        *ulcf = (ngx_http_upload_loc_conf_t*)conf;
    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

	ngx_url_t u;

	

    if ((ulcf->url.len != 0) || (ulcf->url_cv != NULL)) {
        return (char*)"is duplicate";
    }

    value = (ngx_str_t*)cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty value in \"%V\" directive",
                           &cmd->name);

        return (char*)NGX_CONF_ERROR;
    }

    clcf = (ngx_http_core_loc_conf_t*)ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upload_handler;
/**
    if (ngx_http_script_variables_count(&value[1])) {
        // complex value 
        ulcf->url_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (ulcf->url_cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = ulcf->url_cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    } else {
        // simple value 
        ulcf->url = value[1];
    }
**/
	/*********
	 * jin.shang
	 ********/
	//u.url = ulcf->url;
	u.url = value[1];
	u.no_resolve = 1;
	ulcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
	if (ulcf->upstream.upstream == NULL){
		return (char*)NGX_CONF_ERROR;
	}


    return NGX_CONF_OK;
} /* }}} */

ngx_int_t /* {{{ ngx_http_read_upload_client_request_body */
//ngx_http_read_upload_client_request_body(ngx_http_request_t *r) { //ch2
ngx_http_read_upload_client_request_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler) { //change
    ssize_t                    size, preread;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, **next;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_upload_ctx_t     *u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error ngx_http_read_upload_client_request_body entry maincount: %d", r->main->count);
    r->main->count++;

    if (r->request_body || r->discard_body) {
        return NGX_OK;
    }

    rb = (ngx_http_request_body_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body = rb;

    if (r->headers_in.content_length_n <= 0) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_BAD_REQUEST;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->rest = 0;
     */

	rb->post_handler = post_handler; //jin.shang change
    preread = r->header_in->last - r->header_in->pos;

	//gdb 跟踪preread=0
    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        u->received = preread;

        b = (ngx_buf_t*)ngx_calloc_buf(r->pool);
        if (b == NULL) {
            upload_shutdown_ctx(u);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->temporary = 1;
        b->start = r->header_in->pos;
        b->pos = r->header_in->pos;
        b->last = r->header_in->last;
        b->end = r->header_in->end;

        rb->bufs = ngx_alloc_chain_link(r->pool);
        if (rb->bufs == NULL) {
            upload_shutdown_ctx(u);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rb->bufs->buf = b;
        rb->bufs->next = NULL;
        rb->buf = b;

        if (preread >= r->headers_in.content_length_n) {

            /* the whole request body was pre-read */

            r->header_in->pos += r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;

            if (ngx_http_process_request_body(r, rb->bufs) != NGX_OK) {
                upload_shutdown_ctx(u);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            upload_shutdown_ctx(u);

            //return ngx_http_upload_body_handler(r);
			post_handler(r); //change
			return NGX_OK;
        }

        /*
         * to not consider the body as pipelined request in
         * ngx_http_set_keepalive()
         */
        r->header_in->pos = r->header_in->last;

        r->request_length += preread;

        rb->rest = r->headers_in.content_length_n - preread;

        if (rb->rest <= (off_t) (b->end - b->last)) {

            /* the whole request body may be placed in r->header_in */

            rb->to_write = rb->bufs;

            r->read_event_handler = ngx_http_read_upload_client_request_body_handler;

            return ngx_http_do_read_upload_client_request_body(r);
        }

        next = &rb->bufs->next;

    } else {
        b = NULL;
        rb->rest = r->headers_in.content_length_n;
        next = &rb->bufs;
    }

    clcf = (ngx_http_core_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2; //现在size变成10240

    if (rb->rest < (ssize_t) size) {
        size = rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
		//因为图片大小很大，所以会执行这个分支
        size = clcf->client_body_buffer_size;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error size: %d", size);
        /* disable copying buffer for r->request_body_in_single_buf */
        b = NULL;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->buf = rb->buf;
    cl->next = NULL;

    if (b && r->request_body_in_single_buf) {
        size = b->last - b->pos;
        ngx_memcpy(rb->buf->pos, b->pos, size);
        rb->buf->last += size;

        next = &rb->bufs;
    }

    *next = cl;

    rb->to_write = rb->bufs;

    r->read_event_handler = ngx_http_read_upload_client_request_body_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xxxxxxxxxxxxxxxxxxxxxxxxxxx");
    //return ngx_http_do_read_upload_client_request_body(r); //ch2
    ngx_int_t rc = ngx_http_do_read_upload_client_request_body(r); //change
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xxxxx maincount: %d", r->main->count);
      r->main->count--;
    } 
    return rc;
} /* }}} */

static void /* {{{ ngx_http_read_upload_client_request_body_handler */
ngx_http_read_upload_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_http_upload_ctx_t     *u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);
    ngx_event_t               *rev = r->connection->read;
    ngx_http_core_loc_conf_t  *clcf;
    if (rev->timedout) {
        if(!rev->delayed) {
            r->connection->timedout = 1;
            upload_shutdown_ctx(u);
            ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
            return;
        }

        rev->timedout = 0;
        rev->delayed = 0;

        if (!rev->ready) {
            clcf = (ngx_http_core_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(rev, clcf->client_body_timeout);

            if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
                upload_shutdown_ctx(u);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }
    else{
        if (r->connection->read->delayed) {
            clcf = (ngx_http_core_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "http read delayed");

            if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
                upload_shutdown_ctx(u);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }
    //这是nginx自带的
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error finalize 4");
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    } 

    //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error --------------------------------------");
    rc = ngx_http_do_read_upload_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        upload_shutdown_ctx(u);
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error finalize 1");
        ngx_http_finalize_request(r, rc);
    }
} /* }}} */

static ngx_int_t /* {{{ ngx_http_do_read_upload_client_request_body */
ngx_http_do_read_upload_client_request_body(ngx_http_request_t *r)
{
    ssize_t                     size, n, limit;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_upload_ctx_t     *u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_msec_t                 delay;

    c = r->connection;
    rb = r->request_body;

    //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
      //             "error http read client request body");

    for ( ;; ) {
        //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "error -----------------------------------------");
        for ( ;; ) {

            //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "error ***************************************************");
            if (rb->buf->last == rb->buf->end) {

                rc = ngx_http_process_request_body(r, rb->to_write);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "error rc: %d", rc);
              

                switch(rc) {
                    case NGX_OK:
                        break;
                    case NGX_UPLOAD_MALFORMED:
                        return NGX_HTTP_BAD_REQUEST;
                    case NGX_UPLOAD_TOOLARGE:
                        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                    case NGX_UPLOAD_IOERROR:
                        return NGX_HTTP_SERVICE_UNAVAILABLE;
                    case NGX_UPLOAD_NOMEM: case NGX_UPLOAD_SCRIPTERROR:
                    default:
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->to_write = rb->bufs->next ? rb->bufs->next : rb->bufs;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;
            //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "error size: %d", size);

            if ((off_t)size > rb->rest) {
                size = (size_t)rb->rest;
            }
/**
            if (u->limit_rate) {
                limit = u->limit_rate * (ngx_time() - r->start_sec + 1) - u->received;

                if (limit < 0) {
                    c->read->delayed = 1;
                    ngx_add_timer(c->read,
                                  (ngx_msec_t) (- limit * 1000 / u->limit_rate + 1));

                    return NGX_AGAIN;
                }

                if(limit > 0 && size > limit) {
                    size = limit;
                }
            }
**/
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "this is recv: %d", size);
            n = c->recv(c, rb->buf->last, size);

            //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
              //             "error http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client closed prematurely connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            rb->rest -= n;
            r->request_length += n;
            u->received += n;

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
/**
            if (u->limit_rate) {
                delay = (ngx_msec_t) (n * 1000 / u->limit_rate + 1);

                if (delay > 0) {
                    c->read->delayed = 1;
                    ngx_add_timer(c->read, delay);
                    return NGX_AGAIN;
                }
            }
**/
        }//内循环结束

        //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
          //             "error http client request body rest %uz", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {
            clcf = (ngx_http_core_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }//外循环结束

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "error read body end");
    rc = ngx_http_process_request_body(r, rb->to_write);

    switch(rc) {
        case NGX_OK:
            break;
        case NGX_UPLOAD_MALFORMED:
            return NGX_HTTP_BAD_REQUEST;
        case NGX_UPLOAD_TOOLARGE:
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        case NGX_UPLOAD_IOERROR:
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        case NGX_UPLOAD_NOMEM: case NGX_UPLOAD_SCRIPTERROR:
        default:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    upload_shutdown_ctx(u);

    //return ngx_http_upload_body_handler(r);
    //return ngx_http_upload_form_handler(r); //ch2
	rb->post_handler(r);//change
	return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_process_request_body */
ngx_http_process_request_body(ngx_http_request_t *r, ngx_chain_t *body)
{
    ngx_int_t rc;
    ngx_http_upload_ctx_t     *u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    // Feed all the buffers into data handler
    while(body) {
        rc = u->data_handler(u, body->buf->pos, body->buf->last);

        if(rc != NGX_OK)
            return rc;

        body = body->next;
    }

    if(u->raw_input) {
        // Signal end of body
        if(r->request_body->rest == 0) {
            rc = u->data_handler(u, NULL, NULL);

            if(rc != NGX_OK)
                return rc;
        }
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t upload_parse_content_disposition(ngx_http_upload_ctx_t *upload_ctx, ngx_str_t *content_disposition) { /* {{{ */
    char *filename_start, *filename_end;
    char *fieldname_start, *fieldname_end;
    char *p, *q;

    p = (char*)content_disposition->data;

    if(strncasecmp(FORM_DATA_STRING, p, sizeof(FORM_DATA_STRING)-1) && 
            strncasecmp(ATTACHMENT_STRING, p, sizeof(ATTACHMENT_STRING)-1)) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "Content-Disposition is not form-data or attachment");
        return NGX_UPLOAD_MALFORMED;
    }

    filename_start = strstr(p, FILENAME_STRING);

    if(filename_start != 0) {
        
        filename_start += sizeof(FILENAME_STRING)-1;

        filename_end = filename_start + strcspn(filename_start, "\"");

        if(*filename_end != '\"') {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "malformed filename in part header");
            return NGX_UPLOAD_MALFORMED;
        }

        /*
         * IE sends full path, strip path from filename 
         * Also strip all UNIX path references
         */
        for(q = filename_end-1; q > filename_start; q--)
            if(*q == '\\' || *q == '/') {
                filename_start = q+1;
                break;
            }

        upload_ctx->file_name.len = filename_end - filename_start;
        upload_ctx->file_name.data = (u_char*)ngx_palloc(upload_ctx->request->pool, upload_ctx->file_name.len + 1);
        
        if(upload_ctx->file_name.data == NULL)
            return NGX_UPLOAD_NOMEM;

        strncpy((char*)upload_ctx->file_name.data, filename_start, filename_end - filename_start);
    }

    fieldname_start = p;

//    do{
        fieldname_start = strstr(fieldname_start, FIELDNAME_STRING);
//    }while((fieldname_start != 0) && (fieldname_start + sizeof(FIELDNAME_STRING) - 1 == filename_start));

    if(fieldname_start != 0) {
        fieldname_start += sizeof(FIELDNAME_STRING)-1;

        if(fieldname_start != filename_start) {
            fieldname_end = fieldname_start + strcspn(fieldname_start, "\"");

            if(*fieldname_end != '\"') {
                ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0,
                               "malformed fieldname in part header");
                return NGX_UPLOAD_MALFORMED;
            }

            upload_ctx->field_name.len = fieldname_end - fieldname_start;
            upload_ctx->field_name.data = (u_char*)ngx_pcalloc(upload_ctx->request->pool, upload_ctx->field_name.len + 1);

            if(upload_ctx->field_name.data == NULL)
                return NGX_UPLOAD_NOMEM;

            strncpy((char*)upload_ctx->field_name.data, fieldname_start, fieldname_end - fieldname_start);
        }
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t upload_parse_part_header(ngx_http_upload_ctx_t *upload_ctx, char *header, char *header_end) { /* {{{ */
    ngx_str_t s;

    if(!strncasecmp(CONTENT_DISPOSITION_STRING, header, sizeof(CONTENT_DISPOSITION_STRING) - 1)) {
        char *p = header + sizeof(CONTENT_DISPOSITION_STRING) - 1;

        p += strspn(p, " ");
        
        s.data = (u_char*)p;
        s.len = header_end - p;

        if(upload_parse_content_disposition(upload_ctx, &s) != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "invalid Content-Disposition header");
            return NGX_UPLOAD_MALFORMED;
        }
    }
    else if(!strncasecmp(CONTENT_TYPE_STRING, header, sizeof(CONTENT_TYPE_STRING)-1)) {
        char *content_type_str = header + sizeof(CONTENT_TYPE_STRING)-1;
        
        content_type_str += strspn(content_type_str, " ");
        upload_ctx->content_type.len = header_end - content_type_str;
        
        if(upload_ctx->content_type.len == 0) {
            ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0,
                           "empty Content-Type in part header");
            return NGX_UPLOAD_MALFORMED; // Empty Content-Type field
        }

        upload_ctx->content_type.data = (u_char*)ngx_pcalloc(upload_ctx->request->pool, upload_ctx->content_type.len + 1);
        
        if(upload_ctx->content_type.data == NULL)
            return NGX_UPLOAD_NOMEM; // Unable to allocate memory for string

        strncpy((char*)upload_ctx->content_type.data, content_type_str, upload_ctx->content_type.len);
    }

    return NGX_OK;
} /* }}} */

static void upload_discard_part_attributes(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    upload_ctx->file_name.len = 0;
    upload_ctx->file_name.data = NULL;

    upload_ctx->field_name.len = 0;
    upload_ctx->field_name.data = NULL;

    upload_ctx->content_type.len = 0;
    upload_ctx->content_type.data = NULL;

    upload_ctx->content_range.len = 0;
    upload_ctx->content_range.data = NULL;

    upload_ctx->session_id.len = 0;
    upload_ctx->session_id.data = NULL;

    upload_ctx->partial_content = 0;
} /* }}} */

static ngx_int_t upload_start_file(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->start_part_f)
        return upload_ctx->start_part_f(upload_ctx);
    else
        return NGX_OK;
} /* }}} */

static void upload_finish_file(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    // Call user-defined event handler
    if(upload_ctx->finish_part_f)
        upload_ctx->finish_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

static void upload_abort_file(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->abort_part_f)
        upload_ctx->abort_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

//传给flush_output_buffer_f的buf每次起始地址都一样，意味着每次都利用了同一块内存，那么，就要找到每次给这块内存的数据是从哪里获得的
static void upload_flush_output_buffer(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
	
    if(upload_ctx->output_buffer_pos > upload_ctx->output_buffer) {
        if(upload_ctx->flush_output_buffer_f)
            if(upload_ctx->flush_output_buffer_f(upload_ctx, (u_char*)upload_ctx->output_buffer, 
                (size_t)(upload_ctx->output_buffer_pos - upload_ctx->output_buffer)) != NGX_OK)
                upload_ctx->discard_data = 1;

        upload_ctx->output_buffer_pos = upload_ctx->output_buffer;	
    }
} /* }}} */

static void upload_init_ctx(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    upload_ctx->boundary.data = upload_ctx->boundary_start = upload_ctx->boundary_pos = 0;

	upload_ctx->state = upload_state_boundary_seek;

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;

	upload_ctx->start_part_f = ngx_http_upload_start_handler;
	upload_ctx->finish_part_f = ngx_http_upload_finish_handler;
	upload_ctx->abort_part_f = ngx_http_upload_abort_handler;
	upload_ctx->flush_output_buffer_f = ngx_http_upload_flush_output_buffer;

    upload_ctx->started = 0;
    upload_ctx->unencoded = 0;
    /*
     * Set default data handler
     */
    upload_ctx->data_handler = upload_process_buf;
} /* }}} */

static void upload_shutdown_ctx(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
	if(upload_ctx != 0) {
        // Abort file if we still processing it
        if(upload_ctx->state == upload_state_data) {
			//此分支不会执行
            upload_flush_output_buffer(upload_ctx);
            upload_abort_file(upload_ctx);
        }

        upload_discard_part_attributes(upload_ctx);
	}
} /* }}} */

static ngx_int_t upload_start(ngx_http_upload_ctx_t *upload_ctx, ngx_http_upload_loc_conf_t *ulcf) { /* {{{ */
	if(upload_ctx == NULL)
		return NGX_ERROR;

	upload_ctx->header_accumulator = (u_char*)ngx_pcalloc(upload_ctx->request->pool, ulcf->max_header_len + 1);

	if(upload_ctx->header_accumulator == NULL)
		return NGX_ERROR;

	upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
	upload_ctx->header_accumulator_end = upload_ctx->header_accumulator + ulcf->max_header_len;

	upload_ctx->output_buffer = (u_char*)ngx_pcalloc(upload_ctx->request->pool, ulcf->buffer_size);

	if(upload_ctx->output_buffer == NULL)
		return NGX_ERROR;

    upload_ctx->output_buffer_pos = upload_ctx->output_buffer;
    upload_ctx->output_buffer_end = upload_ctx->output_buffer + ulcf->buffer_size;

    upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;

    upload_ctx->range_header_buffer = (u_char*)ngx_pcalloc(upload_ctx->request->pool, ulcf->range_header_buffer_size);

	if(upload_ctx->range_header_buffer == NULL)
		return NGX_ERROR;

    upload_ctx->range_header_buffer_pos = upload_ctx->range_header_buffer;
    upload_ctx->range_header_buffer_end = upload_ctx->range_header_buffer + ulcf->range_header_buffer_size;

    upload_ctx->first_part = 1;

	return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_validate_session_id */
ngx_http_upload_validate_session_id(ngx_str_t *session_id) {
    u_char *p, *q;

    p = session_id->data;
    q = session_id->data + session_id->len;

    while(p != q) {
        if(!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
            || *p == '_' || *p == '-'))
        {
            return NGX_ERROR;
        }

        p++;
    }

    return NGX_OK;
}

static ngx_int_t upload_parse_request_headers(ngx_http_upload_ctx_t *upload_ctx, ngx_http_headers_in_t *headers_in) { /* {{{ */
    ngx_str_t                 *content_type, s;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_uint_t                 i;
    u_char                    *mime_type_end_ptr;
    u_char                    *boundary_start_ptr, *boundary_end_ptr;
    ngx_atomic_uint_t          boundary;
    ngx_http_upload_loc_conf_t *ulcf;

    ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(upload_ctx->request, ngx_http_upload_module);

    // Check whether Content-Type header is missing
    if(headers_in->content_type == NULL) {
        ngx_log_error(NGX_LOG_ERR, upload_ctx->log, ngx_errno,
                      "missing Content-Type header");
        return NGX_HTTP_BAD_REQUEST;
    }

    content_type = &headers_in->content_type->value;

    if(ngx_strncasecmp(content_type->data, (u_char*) MULTIPART_FORM_DATA_STRING,
        sizeof(MULTIPART_FORM_DATA_STRING) - 1)) {
		//此分支是当content_type不是multipart/form-data时
		if(!ngx_strncasecmp(content_type->data, (u_char*) OCTET_STREAM_STRING, sizeof(OCTET_STREAM_STRING) - 1)) {
    		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, upload_ctx->request->connection->log, 0, "octet_stream called - [error]");
			upload_ctx->is_octet_stream = 1;
            //return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
			return NGX_OK;
		}
		if(!ngx_strncasecmp(content_type->data, (u_char*) URLENCODED_STRING, sizeof(URLENCODED_STRING) - 1)) {
    		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, upload_ctx->request->connection->log, 0, "urlencoded called - [error]");
			upload_ctx->is_urlencoded = 1;
            //return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
			return NGX_OK;
		}


        if(!ulcf->resumable_uploads) {
            ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0,
                "Content-Type is not multipart/form-data and resumable uploads are off: %V", content_type);
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }
        /*
         * Content-Type is not multipart/form-data,
         * look for Content-Disposition header now
         */
        part = &headers_in->headers.part;
        header = (ngx_table_elt_t*)part->elts;

        for (i = 0;;i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                  break;
                }

                part = part->next;
                header = (ngx_table_elt_t*)part->elts;
                i = 0;
            }

            if(!strncasecmp(CONTENT_DISPOSITION_STRING, (char*)header[i].key.data, sizeof(CONTENT_DISPOSITION_STRING) - 1 - 1)) {
                if(upload_parse_content_disposition(upload_ctx, &header[i].value)) {
                    ngx_log_error(NGX_LOG_INFO, upload_ctx->log, 0,
                        "invalid Content-Disposition header");
                    return NGX_ERROR;
                }

                upload_ctx->is_file = 1;
                upload_ctx->unencoded = 1;
                upload_ctx->raw_input = 1;
        
                upload_ctx->data_handler = upload_process_raw_buf;
            }else if(!strncasecmp(SESSION_ID_STRING, (char*)header[i].key.data, sizeof(SESSION_ID_STRING) - 1 - 1)
                || !strncasecmp(X_SESSION_ID_STRING, (char*)header[i].key.data, sizeof(X_SESSION_ID_STRING) - 1 - 1))
            {
                if(header[i].value.len == 0) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "empty Session-ID in header");
                    return NGX_ERROR;
                }

                if(ngx_http_upload_validate_session_id(&header[i].value) != NGX_OK) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "invalid Session-ID in header");
                    return NGX_ERROR;
                }

                upload_ctx->session_id = header[i].value;

                ngx_log_debug1(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                               "session id %V", &upload_ctx->session_id);
            }else if(!strncasecmp(CONTENT_RANGE_STRING, (char*)header[i].key.data, sizeof(CONTENT_RANGE_STRING) - 1 - 1) 
                || !strncasecmp(X_CONTENT_RANGE_STRING, (char*)header[i].key.data, sizeof(X_CONTENT_RANGE_STRING) - 1 - 1))
            {
                if(header[i].value.len == 0) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "empty Content-Range in part header");
                    return NGX_ERROR;
                }

                if(strncasecmp((char*)header[i].value.data, BYTES_UNIT_STRING, sizeof(BYTES_UNIT_STRING) - 1)) {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "unsupported range unit");
                    return NGX_ERROR;
                }

                s.data = (u_char*)(char*)header[i].value.data + sizeof(BYTES_UNIT_STRING) - 1;
                s.len = header[i].value.len - sizeof(BYTES_UNIT_STRING) + 1;

                if(ngx_http_upload_parse_range(&s, &upload_ctx->content_range_n) != NGX_OK) {
                    ngx_log_debug2(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "invalid range %V (%V)", &s, &header[i].value);
                    return NGX_ERROR;
                }

                ngx_log_debug3(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                               "partial content, range %O-%O/%O", upload_ctx->content_range_n.start, 
                               upload_ctx->content_range_n.end, upload_ctx->content_range_n.total);

                if(ulcf->max_file_size != 0 && upload_ctx->content_range_n.total > ulcf->max_file_size) {
                    ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0,
                                  "entity length is too big");
                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                upload_ctx->partial_content = 1;
            }
        }

        if(!upload_ctx->unencoded) {
            ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0,
                           "Content-Type is not multipart/form-data and no Content-Disposition header found");
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        upload_ctx->content_type = *content_type;

        boundary = ngx_next_temp_number(0);

        content_type->data =
            (u_char*)ngx_pnalloc(upload_ctx->request->pool,
                        sizeof(MULTIPART_FORM_DATA_STRING "; boundary=") - 1
                        + NGX_ATOMIC_T_LEN);

        if (content_type->data == NULL) {
            return NGX_ERROR;
        }

        content_type->len =
                       ngx_sprintf(content_type->data,
                                   MULTIPART_FORM_DATA_STRING "; boundary=%0muA",
                                   boundary)
                       - content_type->data;

        boundary_start_ptr = content_type->data + sizeof(MULTIPART_FORM_DATA_STRING "; boundary=") - 1;
        boundary_end_ptr = content_type->data + content_type->len;
    }
    else{
		//此分支是当content_type是multipart/form-data时
        // Find colon in content type string, which terminates mime type
        mime_type_end_ptr = (u_char*) ngx_strchr(content_type->data, ';');

        upload_ctx->boundary.data = 0;

        if(mime_type_end_ptr == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "no boundary found in Content-Type");
            return NGX_UPLOAD_MALFORMED;
        }

        boundary_start_ptr = ngx_strstrn(mime_type_end_ptr, BOUNDARY_STRING, sizeof(BOUNDARY_STRING) - 2);

        if(boundary_start_ptr == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "no boundary found in Content-Type");
            return NGX_UPLOAD_MALFORMED; // No boundary found
        }

        boundary_start_ptr += sizeof(BOUNDARY_STRING) - 1;
        boundary_end_ptr = boundary_start_ptr + strcspn((char*)boundary_start_ptr, " ;\n\r");

        if(boundary_end_ptr == boundary_start_ptr) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "boundary is empty");
            return NGX_UPLOAD_MALFORMED;
        }
    }

    // Allocate memory for entire boundary plus \r\n-- plus terminating character
    upload_ctx->boundary.len = boundary_end_ptr - boundary_start_ptr + 4;
    upload_ctx->boundary.data = (u_char*)ngx_palloc(upload_ctx->request->pool, upload_ctx->boundary.len + 1);

    if(upload_ctx->boundary.data == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_cpystrn(upload_ctx->boundary.data + 4, boundary_start_ptr,
        boundary_end_ptr - boundary_start_ptr + 1);
    
    // Prepend boundary data by \r\n--
    upload_ctx->boundary.data[0] = '\r'; 
    upload_ctx->boundary.data[1] = '\n'; 
    upload_ctx->boundary.data[2] = '-'; 
    upload_ctx->boundary.data[3] = '-'; 

    /*
     * NOTE: first boundary doesn't start with \r\n. Here we
     * advance 2 positions forward. We will return 2 positions back 
     * later
     */
    upload_ctx->boundary_start = upload_ctx->boundary.data + 2;
    upload_ctx->boundary_pos = upload_ctx->boundary_start;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_parse_range */
ngx_http_upload_parse_range(ngx_str_t *range, ngx_http_upload_range_t *range_n)
{
    u_char *p = range->data;
    u_char *last = range->data + range->len;
    off_t  *field = &range_n->start;

    if(range_n == NULL)
        return NGX_ERROR;

    do{
        *field = 0;

        while(p < last) {

            if(*p >= '0' && *p <= '9') {
                (*field) = (*field) * 10 + (*p - '0');
            }
            else if(*p == '-') {
                if(field != &range_n->start) {
                    return NGX_ERROR;
                }

                field = &range_n->end;
                p++;
                break;
            }
            else if(*p == '/') {
                if(field != &range_n->end) {
                    return NGX_ERROR;
                }

                field = &range_n->total;
                p++;
                break;
            }
            else {
                return NGX_ERROR;
            }

            p++;
        }
    }while(p < last);

    if(field != &range_n->total) {
        return NGX_ERROR;
    }

    if(range_n->start >= range_n->end || range_n->start >= range_n->total
        || range_n->end > range_n->total)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
} /* }}} */

static void upload_putc(ngx_http_upload_ctx_t *upload_ctx, u_char c) { /* {{{ */
    if(!upload_ctx->discard_data) {
        *upload_ctx->output_buffer_pos = c;

        upload_ctx->output_buffer_pos++;

        if(upload_ctx->output_buffer_pos == upload_ctx->output_buffer_end) {
			//此分支会执行，每当读到一个buf大小后，就开始调用flush
            upload_flush_output_buffer(upload_ctx);	
		}
    }
} /* }}} */

static ngx_int_t upload_process_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end) { /* {{{ */
  //ngx_log_debug1(NGX_LOG_DEBUG_CORE, upload_ctx->request->connection->log, 0, "error buf size: %d", end-start);

	u_char *p;
    ngx_int_t rc;

	// No more data?
	if(start == end) {
		if(upload_ctx->state != upload_state_finish) {
            ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0, "premature end of body");
			return NGX_UPLOAD_MALFORMED; // Signal error if still haven't finished
        }
		else
			return NGX_OK; // Otherwise confirm end of stream
    }

	for(p = start; p != end; p++) {
		switch(upload_ctx->state) {
			/*
			 * Seek the boundary
			 */
			case upload_state_boundary_seek:
				if(*p == *upload_ctx->boundary_pos) 
					upload_ctx->boundary_pos++;
				else
					upload_ctx->boundary_pos = upload_ctx->boundary_start;

				if(upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
					upload_ctx->state = upload_state_after_boundary;
					upload_ctx->boundary_start = upload_ctx->boundary.data;
					upload_ctx->boundary_pos = upload_ctx->boundary_start;
				}
				break;
			case upload_state_after_boundary:
				switch(*p) {
					case '\n':
						upload_ctx->state = upload_state_headers;
                        upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
					case '\r':
						break;
					case '-':
						upload_ctx->state = upload_state_finish;
						break;
				}
				break;
			/*
			 * Collect and store headers
			 */
			case upload_state_headers:
				switch(*p) {
					case '\n':
						if(upload_ctx->header_accumulator_pos == upload_ctx->header_accumulator) {
                            upload_ctx->is_file = (upload_ctx->file_name.data == 0) || (upload_ctx->file_name.len == 0) ? 0 : 1;

							//当一张图片的数据读到\n时，就判断是否整张图片已经读完，如果读完则调用下面的函数创建一个文件来保存图片
							//真正写图片数据是在下面upload_flush_output_buffer中执行
                            rc = upload_start_file(upload_ctx);
                            
                            if(rc != NGX_OK) {
                                upload_ctx->state = upload_state_finish;
                                return rc; // User requested to cancel processing
                            } else {
                                upload_ctx->state = upload_state_data;
                                upload_ctx->output_buffer_pos = upload_ctx->output_buffer;	
                            }
                        } else {
                            *upload_ctx->header_accumulator_pos = '\0';

                            rc = upload_parse_part_header(upload_ctx, (char*)upload_ctx->header_accumulator,
                                (char*)upload_ctx->header_accumulator_pos);

                            if(rc != NGX_OK) {
                                upload_ctx->state = upload_state_finish;
                                return rc; // Malformed header
                            } else
                                upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
                        }
					case '\r':
						break;
					default:
						if(upload_ctx->header_accumulator_pos < upload_ctx->header_accumulator_end - 1)
							*upload_ctx->header_accumulator_pos++ = *p;
						else {
                            ngx_log_error(NGX_LOG_ERR, upload_ctx->log, 0, "part header is too long");

                            upload_ctx->state = upload_state_finish;
							return NGX_UPLOAD_MALFORMED;
                        }
						break;
				}
				break;
			/*
			 * Search for separating or terminating boundary
			 * and output data simultaneously
			 */
			case upload_state_data:
				if(*p == *upload_ctx->boundary_pos) 
					upload_ctx->boundary_pos++;
				else {
					if(upload_ctx->boundary_pos == upload_ctx->boundary_start) {
                        // IE 5.0 bug workaround
                        if(*p == '\n') {
                            /*
                             * Set current matched position beyond LF and prevent outputting
                             * CR in case of unsuccessful match by altering boundary_start 
                             */ 
                            upload_ctx->boundary_pos = upload_ctx->boundary.data + 2;
                            upload_ctx->boundary_start = upload_ctx->boundary.data + 1;
                        } else
                            upload_putc(upload_ctx, *p);
                    } else {
						// Output partially matched lump of boundary
						u_char *q;
						for(q = upload_ctx->boundary_start; q != upload_ctx->boundary_pos; q++)
							upload_putc(upload_ctx, *q);

                        p--; // Repeat reading last character

						// And reset matched position
                        upload_ctx->boundary_start = upload_ctx->boundary.data;
						upload_ctx->boundary_pos = upload_ctx->boundary_start;
					}
				}

				if(upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
					upload_ctx->state = upload_state_after_boundary;
					upload_ctx->boundary_pos = upload_ctx->boundary_start;
					
					//ngx_log_debug0(NGX_LOG_DEBUG_HTTP, upload_ctx->request->connection->log, 0, "error flush flush");
					//当剩余的图片数据不足以一个buf时，会调用该flush
                    upload_flush_output_buffer(upload_ctx);
                    if(!upload_ctx->discard_data) {
					//ngx_log_debug0(NGX_LOG_DEBUG_HTTP, upload_ctx->request->connection->log, 0, "error no discard_data");
                        upload_finish_file(upload_ctx);
					}
                    else {
					//ngx_log_debug0(NGX_LOG_DEBUG_HTTP, upload_ctx->request->connection->log, 0, "error discard_data");
                        upload_abort_file(upload_ctx);
					}
				}
				break;
			/*
			 * Skip trailing garbage
			 */
			case upload_state_finish:
				break;
		}
	}

	return NGX_OK;
} /* }}} */
//此函数不会执行
static ngx_int_t
upload_process_raw_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end) { /* {{{ */
    ngx_int_t rc;

	if(start == end) {
        if(!upload_ctx->discard_data)
            upload_finish_file(upload_ctx);
        else
            upload_abort_file(upload_ctx);
        return NGX_OK;
    }

    if(!upload_ctx->started) {
        rc = upload_start_file(upload_ctx);
        
        if(rc != NGX_OK) {
            return rc;
        }

        upload_ctx->started = 1;
    }

    if(upload_ctx->flush_output_buffer_f)
        if(upload_ctx->flush_output_buffer_f(upload_ctx, (u_char*)start, 
            (size_t)(end - start)) != NGX_OK)
            upload_ctx->discard_data = 1;

    return NGX_OK;

} /* }}} */

static void /* {{{ ngx_upload_cleanup_handler */
ngx_upload_cleanup_handler(void *data)
{
    ngx_upload_cleanup_t        *cln = (ngx_upload_cleanup_t*)data;
    ngx_uint_t                  i;
    uint16_t                    *s;
    u_char                      do_cleanup = 0;

    if(!cln->aborted) {
        if(cln->fd >= 0) {
            if (ngx_close_file(cln->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, cln->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed", cln->filename);
            }
        }

        if(cln->cleanup_statuses != NULL) {
            s = (uint16_t*)cln->cleanup_statuses->elts;

            for(i = 0; i < cln->cleanup_statuses->nelts; i++) {
                if(cln->headers_out->status == s[i]) {
                    do_cleanup = 1;
                }
            }
        }

        if(do_cleanup) {
                if(ngx_delete_file(cln->filename) == NGX_FILE_ERROR) { 
                    ngx_log_error(NGX_LOG_ERR, cln->log, ngx_errno
                        , "failed to remove destination file \"%s\" after http status %l"
                        , cln->filename
                        , cln->headers_out->status
                        );
                }else
                    ngx_log_error(NGX_LOG_INFO, cln->log, 0
                        , "finished cleanup of file \"%s\" after http status %l"
                        , cln->filename
                        , cln->headers_out->status
                        );
        }
    }
} /* }}} */

static ngx_int_t
ngx_http_upload_create_request(ngx_http_request_t* r)
{
 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error fuck 1");
	ngx_buf_t *b;
	ngx_chain_t *cl;
	ngx_http_upstream_t *u;
	ngx_http_upload_ctx_t     *ctx;
	ctx = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);
	static ngx_str_t backendQueryLine = ngx_string("POST /hello HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\nAccept-Encoding: identity\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Python-urllib/2.7\r\n\r\n");
	//记住，请求结束要用\r\n\r\n
	u = r->upstream;
	b = ngx_create_temp_buf(r->pool, backendQueryLine.len);
	if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    u->request_bufs = cl;
	b->last = ngx_copy(b->pos, backendQueryLine.data, backendQueryLine.len);
	/**
	*b->last++ = 'p'; *b->last++ = 'o'; *b->last++ = 's'; *b->last++ = 't'; *b->last++ = ' '; *b->last++ = '/'; *b->last++ = ' '; *b->last++ = 'H'; *b->last++ = 'T'; *b->last++ = 'T'; *b->last++ = 'P'; *b->last++ = '/'; *b->last++='1'; *b->last++ = '.'; *b->last++ = '0';
	*b->last++ = CR; *b->last++ = LF;
	
	b->last = ngx_copy(b->last, ctx->pic, 30208);
	*b->last++ = CR; *b->last++ = LF;
	*b->last++ = CR; *b->last++ = LF;
**/
	return NGX_OK;
}
static ngx_int_t
ngx_http_upload_process_header(ngx_http_request_t* r)
{
 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error fuck");
/**
	ngx_http_upload_ctx_t *upload_ctx;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error process_header entry");
    u_char                    *p;
    ngx_http_upstream_t       *u;

    upload_ctx = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    u = r->upstream;
    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF || *p == '\0') {
            goto found;
        }
    }

    return NGX_AGAIN;

found: 
    *p = '\0'; 
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error ngx_http_echo_process_header_OK called");
    //r->headers_out.content_length_n = p - u->buffer.pos;//设置返回给客户端在响应在长度
    u->headers_in.status_n = 200; //u->headers_in将被作为返回给客户端的响应返回状态码
    u->state->status = 200; 
	
    ngx_table_elt_t *h;
    ngx_str_t name = ngx_string("helloHeaders");
    ngx_str_t value = ngx_string("abc");
    h = ngx_list_push(&r->headers_out.headers);
    h->hash = 1;
    h->key.len = name.len;
    h->key.data = name.data;
    h->value.len = value.len;
    h->value.data = value.data;
	
 **/
	return NGX_OK;
}
static void
ngx_http_upload_finalize_request(ngx_http_request_t* r, ngx_int_t rc)
{
	    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_echo_finalize_request called - [error]");
		    return ;
}  
static void 
ngx_http_upload_parse_args(ngx_http_upload_ctx_t *u, u_char *buf, size_t len)
{
	if(!ngx_strncasecmp(buf, (u_char*) PAGETYPE, sizeof(PAGETYPE) - 1)) {
		u->pagetype = (ngx_str_t*)ngx_pcalloc(u->request->pool, sizeof(ngx_str_t));
		u->pagetype->len = len - 9;
		u->pagetype->data = buf + 9;
	    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "[error pagetype] %V", u->pagetype);
	}
	if(!ngx_strncasecmp(buf, (u_char*) HOSTID, sizeof(HOSTID) - 1)) {
		u->hostid = (ngx_str_t*)ngx_pcalloc(u->request->pool, sizeof(ngx_str_t));
		u->hostid->len = len - 7;
		u->hostid->data = buf + 7;
	    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "[error hostid] %V", u->hostid);
	}
	if(!ngx_strncasecmp(buf, (u_char*) UPLOADID, sizeof(UPLOADID) - 1)) {
		u->uploadid = (ngx_str_t*)ngx_pcalloc(u->request->pool, sizeof(ngx_str_t));
		u->uploadid->len = len - 9;
		u->uploadid->data = buf + 9;
	    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "[error uploadid] %V", u->uploadid);
	}
	if(!ngx_strncasecmp(buf, (u_char*) TICK, sizeof(TICK) - 1)) {
		u->tick = (ngx_str_t*)ngx_pcalloc(u->request->pool, sizeof(ngx_str_t));
		u->tick->len = len - 5;
		u->tick->data = buf + 5;
	    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "[error tick] %V", u->tick);
	}
	if(!ngx_strncasecmp(buf, (u_char*) BLOCK_INDEX, sizeof(BLOCK_INDEX) - 1)) {
		u->block_index = (ngx_str_t*)ngx_pcalloc(u->request->pool, sizeof(ngx_str_t));
		u->block_index->len = len - 12;
		u->block_index->data = buf + 12;
	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "[error block_index] %V", u->block_index);
	}
	if(!ngx_strncasecmp(buf, (u_char*) BLOCK_COUNT, sizeof(BLOCK_COUNT) - 1)) {
		u->block_count = (ngx_str_t*)ngx_pcalloc(u->request->pool, sizeof(ngx_str_t));
		u->block_count->len = len - 12;
		u->block_count->data = buf + 12;
	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, u->request->connection->log, 0, "[error block_count] %V", u->block_count);
	}


}

//子请求接收到响应的处理
static ngx_int_t upload_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] ubuntu");
    ngx_http_request_t *pr = r->parent;
    ngx_http_upload_ctx_t *myctx = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(pr, ngx_http_upload_module);
    pr->headers_out.status = r->headers_out.status;
    if(r->headers_out.status == NGX_HTTP_OK)
    {
        //int flag = 0;
        myctx->temp = &r->upstream->buffer;
//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] sub method_name is : %V",  &r->method_name);
//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] sub content-length is : %d",  &r->headers_in.content_length_n);
        /**ngx_buf_t *pRecvBuf = &r->upstream->buffer;
        for(; pRecvBuf->pos != pRecvBuf->last; pRecvBuf->pos++)
        {
            
            
            if(*pRecvBuf->pos == ',' || *pRecvBuf->pos == '\"')
            {
                if(flag > 0)
                    myctx->stock[flag-1].len = pRecvBuf->pos - myctx->stock[flag-1].data;
                flag++;
                myctx->stock[flag-1].data = pRecvBuf->pos + 1;
            }
            if(flag > 6)
                break;
            
        }**/
    }
    pr->write_event_handler = upload_post_handler;
    return NGX_OK;
}

//父请求的处理
static void upload_post_handler(ngx_http_request_t *r) {
	ngx_str_t response = ngx_string("Hello World!!!!!");
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] sub method_name is : 1 %d", response.len);
    if(r->headers_out.status != NGX_HTTP_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error finalize 3");
        ngx_http_finalize_request(r, r->headers_out.status);
        return ;
    }
    ngx_http_upload_ctx_t *myctx = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);

    //ngx_str_t output_format = ngx_string("stock[%V], Today current price: %V, volumn: %V");
    //int bodylen = output_format.len + myctx->stock[0].len + myctx->stock[1].len + myctx->stock[4].len - 6;
    int bodylen = myctx->temp->last - myctx->temp->pos;

    r->headers_out.content_length_n = response.len; //content_length
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, response.len);
    //ngx_snprintf(b->pos, bodylen, (char*)output_format.data, &myctx->stock[0], &myctx->stock[1], &myctx->stock[4]);
    //b->last = b->pos + bodylen;
    b->last = ngx_cpymem(b->pos, response.data, response.len);

    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    static ngx_str_t type = ngx_string("text/plain");
    r->headers_out.content_type = type; //content_type
    r->headers_out.status = NGX_HTTP_OK;

    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] sub method_name is : 2");
    ngx_int_t ret = ngx_http_send_header(r); //sent head
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] sub method_name is id: %d", getpid());
    ret = ngx_http_output_filter(r, &out);   //sent body
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] sub method_name is : 4");
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error finalize 2");
    ngx_http_finalize_request(r, ret);
}

static ngx_int_t ngx_http_upload_form_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error upload form 0000000 ");
	ngx_int_t rc;
	ngx_http_request_body_t   *rb;
	ngx_buf_t *b;
	u_char* post_content = NULL;
	string post_str;
	string header_str;
	ngx_http_upload_ctx_t *myctx = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);
    ngx_http_post_subrequest_t *psr = (ngx_http_post_subrequest_t*)ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if(psr == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    psr->handler = upload_subrequest_post_handler;
    psr->data = myctx;

    ngx_str_t sub_location = ngx_string("/list");
    ngx_http_request_t *sr;

	
	//在构造的请求体中加入第一行：图片个数
	/**
	int size = (int)myctx->images.size();
	char temp[64];
	sprintf(temp, "%d", size);
	post_str = string(temp);
	post_str.append("\n");
	**/

	//在构造的请求体中加入图片数据：一行是路径，一行是数据
  ProccesserResponse resp;
  ProccesserRequest req;
  req._query[PAGETYPE] = "wcytest";
  req._query[HOSTID] = "12345";
  req._query[UPLOADID] = "12345";

	if(images.empty())
		return NGX_HTTP_INTERNAL_SERVER_ERROR;	
	std::vector<std::string>::iterator iter;
	int i = 0;
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xxxxxxxxxxxxxxxxxxxxxxxx: %d ", (int)images.size());
    //req._fileArray.clear();
	for(iter=images.begin();iter!=images.end();iter++){
    	//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xxxxxxxxxxxxxxxxxxxxxxxx: %d ", (*iter).length());
    //file
    upload::ProccesserRequest::UploadFile file;
    file.filename = "test.jpg";
    file.data = *iter;
    req._fileArray.push_back(file);

		//header_str.append("file:").append("/root/jin.shang/").append(num2str(i)).append(".jpg");
		//header_str.append("|size:").append(num2str((*iter).length())).append(" ");
		i++;
	}
  images.clear();

//计算
// aiai
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] compute start");
    UploadAction uploadAction;
    uploadAction.Process(req, resp);
    std::vector<upload::OutFile> files = resp._files;
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error files length: %d ", (int)files.size());
    std::vector<upload::OutFile>::iterator iter_outfile;
    for(iter_outfile = files.begin(); iter_outfile != files.end(); iter_outfile++){
      std::vector<upload::OutImageUrl> images_out = iter_outfile->images_;
    	//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error images_out length: %d ", (int)images_out.size());
      std::vector<upload::OutImageUrl>::iterator iter_image;
      for(iter_image = images_out.begin(); iter_image != images_out.end(); iter_image++){
    	  //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error image data size: %d ", iter_image->data_.length());
        post_str.append(iter_image->data_); 
        //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error image url_ name: %s ", iter_image->url_.substr(26).c_str());
        header_str.append("file:").append("/data/jin.shang/").append(iter_image->url_.substr(26));
        header_str.append("|size:").append(num2str(iter_image->data_.length())).append(" ");
      }
      //images.clear();
    }
    //files.clear();

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] compute end @@@@@@@@@@@@@@@@@@@@@ return code : %d",  resp._code);
    uploadAction.Stop();

  //header_str.append("file:/root/jin.shang/large_uPNg_355e0000027c125c.jpg|size:3"); //aiai
  //post_str.append("def");//aiai

    ngx_str_t name = ngx_string("image");
    ngx_str_t value;
	value.len = header_str.size();
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error lllllllllllllllllllllllllllllllll %s", header_str.c_str());
    //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error lllllllllll");
	value.data = (u_char*)ngx_palloc(r->pool, value.len + 1);
	ngx_cpymem(value.data, header_str.c_str(), value.len);
	value.data[value.len] = '\0';

    //ngx_str_t name = ngx_string("helloHeaders");
	//ngx_str_t value = ngx_string("abc");

    ngx_table_elt_t *h;
    h = (ngx_table_elt_t*)ngx_list_push(&r->headers_in.headers);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error llllllllllllllllllllllllllllllll post_str size: %d", post_str.size());
    h->hash = 1;
    h->key.len = name.len;
    h->key.data = name.data;
    h->value.len = value.len;
    h->value.data = value.data;

    b = ngx_create_temp_buf(r->pool, post_str.size());
    if (b == NULL)
        return NGX_ERROR;
	//b->last = ngx_copy(b->last, myctx->pic, 30208);
	b->last = ngx_copy(b->last, post_str.c_str(), post_str.size());
	//*b->last++ = CR;
	//*b->last++ = LF;
	rb = (ngx_http_request_body_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
	r->request_body = rb;
	rb->bufs = ngx_alloc_chain_link(r->pool);
    if (rb->bufs == NULL)
     	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    rb->bufs->buf = b;
   	rb->bufs->next = NULL;
	rb->buf = b;

  //设定请求的content-length
  //r->headers_in.content_length_n = post_str.size();
  //r->headers_in.content_length_n = 1234567;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error content_length: %d ", r->headers_in.content_length_n);
//r->main->count--;

    rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    //rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr, 0);
    if(rc != NGX_OK)
        return NGX_ERROR;
return NGX_DONE;
    //test
   /** 
    ngx_str_t response = ngx_string("hello world!");
    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_t type = ngx_string("text/plain");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = response.len; //content_length
    ngx_buf_t *bb = ngx_create_temp_buf(r->pool, response.len);
    bb->last = ngx_cpymem(bb->pos, response.data, response.len);
    bb->last_buf = 1;
    ngx_chain_t out;
    out.buf = bb;
    out.next = NULL;

    ngx_http_send_header(r);
    return ngx_http_output_filter(r, &out);
    **/
}
static ngx_int_t ngx_http_upload_stream_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error upload stream or urlencoded 0000000 ");
	ngx_int_t rc;
	ngx_http_request_body_t   *rb;
	ngx_buf_t *b;
	ngx_http_upload_ctx_t *myctx = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);
    ngx_http_post_subrequest_t *psr = (ngx_http_post_subrequest_t*)ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if(psr == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    psr->handler = upload_subrequest_post_handler;
    psr->data = myctx;

    ngx_str_t sub_location = ngx_string("/list");
    ngx_http_request_t *sr;


    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error body content-length: %d ", r->headers_in.content_length_n);
	u_char* post_content = NULL;
	rb = (ngx_http_request_body_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
	rb = r->request_body;
	post_content = (u_char*)ngx_palloc(r->pool, rb->buf->last-rb->buf->pos + 1);
	ngx_cpystrn(post_content, rb->buf->pos, rb->buf->last-rb->buf->pos+1);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error post_content: %s", post_content);


    rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if(rc != NGX_OK)
        return NGX_ERROR;
}

static void upload_parse_header_args(ngx_http_request_t *r) {
	ngx_http_upload_ctx_t     *u;
	u_char *start = r->args.data;
	u_char * p = start;
	u_char * b = (u_char*)ngx_pcalloc(r->pool, 100);
 	u = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module); 
	int i = 0;
	while(i<r->args.len) {
    	if(*p == '&') {
        	//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args len : %d",  p-start);
        	ngx_memcpy(b, start, p-start);
        	ngx_http_upload_parse_args(u, b, p-start);
        	//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args b : %s",  b);
        	p++;
        	start = p;
        	i++;
    	}
    	p++;
    	i++;
	}
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args len : %d",  p-start);
    ngx_memcpy(b, start, p-start);
    ngx_http_upload_parse_args(u, b, p-start);
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] args b : %s",  b);

}

static ngx_int_t ngx_http_upload_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_http_upload_loc_conf_t  *ulcf;

    if (!(r->method & NGX_HTTP_POST))
        return NGX_HTTP_NOT_ALLOWED;

    ngx_http_upload_ctx_t *myctx = (ngx_http_upload_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_upload_module);
	ulcf = (ngx_http_upload_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_upload_module); 
    if(myctx == NULL)
    {
        myctx = (ngx_http_upload_ctx_t*)ngx_palloc(r->pool, sizeof(ngx_http_upload_ctx_t));
        if(myctx == NULL)
            return NGX_ERROR;
        ngx_http_set_ctx(r, myctx, ngx_http_upload_module);
    }
/**
    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if(psr == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    psr->handler = upload_subrequest_post_handler;
    psr->data = myctx;
**/

    /**
    ngx_str_t sub_prefix = ngx_string("/list=");
    ngx_str_t sub_location;
    sub_location.len = sub_prefix.len + r->args.len;
    sub_location.data = ngx_palloc(r->pool, sub_location.len);
    ngx_snprintf(sub_location.data, sub_location.len, "%V%V", &sub_prefix, &r->args);
    **/
/**
    ngx_str_t name = ngx_string("helloHeaders");
    ngx_str_t value = ngx_string("abc");
    ngx_table_elt_t *h;
    h = (ngx_table_elt_t*)ngx_list_push(&r->headers_in.headers);
    h->hash = 1;
    h->key.len = name.len;
    h->key.data = name.data;
    h->value.len = value.len;
    h->value.data = value.data;
**/
    if(ulcf->md5) {
        if(myctx->md5_ctx == NULL) {
            myctx->md5_ctx = (ngx_http_upload_md5_ctx_t*)ngx_palloc(r->pool, sizeof(ngx_http_upload_md5_ctx_t));
            if (myctx->md5_ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        myctx->md5_ctx = NULL;

    if(ulcf->sha1) {
        if(myctx->sha1_ctx == NULL) {
            myctx->sha1_ctx = (ngx_http_upload_sha1_ctx_t*)ngx_palloc(r->pool, sizeof(ngx_http_upload_sha1_ctx_t));
            if (myctx->sha1_ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        myctx->sha1_ctx = NULL;

    myctx->calculate_crc32 = ulcf->crc32;

    myctx->request = r;
    myctx->log = r->connection->log;
    myctx->chain = myctx->last = myctx->checkpoint = NULL;
    myctx->output_body_len = 0;

    myctx->prevent_output = 0;
    myctx->no_content = 1;
    myctx->limit_rate = ulcf->limit_rate;
    myctx->received = 0;
    myctx->ordinal = 0;
	myctx->is_octet_stream = 0;
	myctx->is_urlencoded = 0;
	images.clear();
std::cout<< "haha" << std::endl;

    //初始化各种参数
    //ProccesserRequest req;
    //req._query[PAGETYPE] = "wcytest";
    //req._query[HOSTID] = "12345";
    //req._query[UPLOADID] = "12345";
    //ProccesserResponse resp;
   
    //UploadAction upload;
    //upload.Process(&req, &resp);

	  //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] @@@@@@@@@@@@@@@@@@@@@ return code : %d",  resp.code);
    //upload.Stop();
    std::cout << "finish" << std::endl;
/////////////////////////////////////////////

	upload_init_ctx(myctx);
	//解析头，找出content-type
  	rc = upload_parse_request_headers(myctx, &r->headers_in);
	if(rc != NGX_OK) {
        upload_shutdown_ctx(myctx);
        return rc;
    }    
	//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] 2 args is : %V",  &r->args);
	//解析args
	upload_parse_header_args(r);

    if(upload_start(myctx, ulcf) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error xoxoxoxoxoxo 1 2 3 4 5 6 ");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }    

	if(myctx->is_octet_stream || myctx->is_urlencoded){

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error ----------------------------------------------------- ");
		//rc = ngx_http_read_client_request_body(r, (ngx_http_client_body_handler_pt)ngx_http_upload_stream_handler); change
	}else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ");
		rc = ngx_http_read_upload_client_request_body(r, (ngx_http_client_body_handler_pt)ngx_http_upload_form_handler); //change
		//rc = ngx_http_read_upload_client_request_body(r); //ch2
	}
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}    
	  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[error] method_name is : %V",  &r->method_name);
    return NGX_DONE;
}          
static char*
ngx_conf_set_echo(ngx_conf_t *cf, ngx_command_t *cmd, void* conf)
{
    ngx_http_core_loc_conf_t*   clcf;
    ngx_http_upload_loc_conf_t        *ulcf = (ngx_http_upload_loc_conf_t*)conf;
    ngx_str_t                         *value;

    ngx_url_t u;
	std::vector<int> v;
	for(int i = 0; i < 10; i++)
		v.push_back(i);

	for(int i = 0; i < 10; i++)
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_conf_set_echo called - [error] %d", i);
    

    if ((ulcf->url.len != 0) || (ulcf->url_cv != NULL)) {
        return "is duplicate";
    }

    value = (ngx_str_t*)cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "empty value in \"%V\" directive",
                           &cmd->name);

        return (char*)NGX_CONF_ERROR;
    }


    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ngx_conf_set_echo called - [error]");

    clcf = (ngx_http_core_loc_conf_t*)ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upload_handler; //设置handler
///////////////////////////////////////
/**
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
             
    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
                      
    h = (ngx_http_handler_pt *)ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    *h = ngx_http_upload_handler;
**/ 
////////////////////////////////////////////
	u.url = value[1];
    u.no_resolve = 1;
//初始化
    int re = g_runtime_config.Load();
    logging::opensyslog("upload.async");

    gDiskCache.Init("conf/diskcache.conf");
    upload::g_blockmanager.Init("conf/blockmemcache.conf");
    upload::g_tickmanager.Init("conf/mc.conf");
    RefererMgr::Instance()->Init("conf/referer.conf");
    xce::Init();


    return NGX_CONF_OK;
}

static std::string num2str(int i)
{
	std::stringstream ss;
	ss << i;
	return ss.str();
}
static ngx_int_t ngx_http_upload_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h; 
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = (ngx_http_handler_pt *)ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }   

    *h = ngx_http_upload_handler;

    return NGX_OK;
}
