
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <gd.h>
#include <math.h>
#include <dirent.h>

#define NGX_HTTP_IMAGE_OFF       0
#define NGX_HTTP_IMAGE_TEST      1
#define NGX_HTTP_IMAGE_SIZE      2
#define NGX_HTTP_IMAGE_RESIZE    3
#define NGX_HTTP_IMAGE_CROP      4
#define NGX_HTTP_IMAGE_ROTATE    5
#define NGX_HTTP_IMAGE_WATERMARK 6

#define NGX_HTTP_IMAGE_START     0
#define NGX_HTTP_IMAGE_READ      1
#define NGX_HTTP_IMAGE_PROCESS   2
#define NGX_HTTP_IMAGE_PASS      3
#define NGX_HTTP_IMAGE_DONE      4


#define NGX_HTTP_IMAGE_NONE      0
#define NGX_HTTP_IMAGE_JPEG      1
#define NGX_HTTP_IMAGE_GIF       2
#define NGX_HTTP_IMAGE_PNG       3
#define NGX_HTTP_IMAGE_WEBP      4


#define NGX_HTTP_IMAGE_BUFFERED  0x08

typedef struct {
    ngx_str_t image;  // 水印图路径，添加图片水印时的必选参数。内容必须是URL安全base64编码。
    ngx_str_t text;  // 水印文字 URL安全base64编码。最大长度为64个字符（支持最多20个左右的汉字）。
    ngx_int_t size;  // 文字大小
    ngx_str_t type;  // 文字字体
    ngx_str_t color; // 文字颜色
    ngx_str_t g;  // 取值为tl、top、tr、left、center、right、bl、bottom、br和random，共10个取值
    ngx_int_t x;  // 距离图片边缘的水平距离，默认左上角为原点。取值范围为[0，4096]。默认值为10。单位为像素（px）。
    ngx_int_t y;  // 距离图片边缘的垂直距离，默认左上角为原点。取值范围为[0，4096]。默认值为10。单位为像素（px）。
    ngx_int_t t;  // 文字或图片水印的透明度。取值范围为[0，100]。默认值为100，100%表示不透明。
    ngx_flag_t fill; // 文字铺满效果，0:以参数g为准，1:铺满整个图片，参数g无效
    ngx_int_t rotate; // 文字水印的按顺时针旋转的角度。取值范围为(0，360)。
    ngx_int_t interval; // 文字的间距。取值范围为[0，1000]
} image_watermark_args;

// 字体全局配置信息
typedef struct{
    ngx_regex_t                  *args_re;         // 请求参数解析正则匹配
    int                          args_captures;         // 请求参数匹配计数
    ngx_regex_t                  *image_process_re;    // x-image-process 参数正则匹配
    int                          image_process_captures;    // x-image-process 参数匹配计数
    ngx_regex_t                  *value_re;         // 参数值正则匹配
    int                          value_captures;         // 参数值匹配计数
    ngx_hash_t                   font_hash;   // 在nginx安装目录下添加fonts目录，所有可用字体均放置到该目录下
} ngx_http_image_filter_main_conf_t;

// 图片插件配置信息元数据
typedef struct {
    ngx_uint_t                   filter;
    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   angle;
    ngx_uint_t                   jpeg_quality;
    ngx_uint_t                   webp_quality;
    ngx_uint_t                   sharpen;   // 图像锐化

    ngx_flag_t                   transparency;  // 是否获取图像透明度
    ngx_flag_t                   interlace;    // 是否支持交织保存

    ngx_int_t           watermark_width_from; // width from use watermark
    ngx_int_t           watermark_height_from; // height from use watermark

    ngx_http_complex_value_t    *wcv;
    ngx_http_complex_value_t    *hcv;
    ngx_http_complex_value_t    *acv;
    ngx_http_complex_value_t    *jqcv;
    ngx_http_complex_value_t    *wqcv;
    ngx_http_complex_value_t    *shcv;

    size_t                       buffer_size;
} ngx_http_image_filter_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;

    size_t                       length;

    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   max_width;
    ngx_uint_t                   max_height;
    ngx_uint_t                   angle;

    ngx_uint_t                   phase;
    ngx_uint_t                   type;
    ngx_uint_t                   force;
} ngx_http_image_filter_ctx_t;


static ngx_int_t ngx_http_image_send(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_uint_t ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t *ngx_http_image_process(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_image_json(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static ngx_buf_t *ngx_http_image_asis(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static void ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t ngx_http_image_size(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);

static ngx_buf_t *ngx_http_image_resize(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static gdImagePtr ngx_http_image_source(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static gdImagePtr ngx_http_image_new(ngx_http_request_t *r, int w, int h,
    int colors);
static u_char *ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type,
    gdImagePtr img, int *size);
static void ngx_http_image_cleanup(void *data);
static ngx_uint_t ngx_http_image_filter_get_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v);
static ngx_uint_t ngx_http_image_filter_value(ngx_str_t *value);


static void *ngx_http_image_filter_main_create_conf(ngx_conf_t *cf);
static void *ngx_http_image_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_image_filter_jpeg_quality(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_image_filter_webp_quality(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_image_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_image_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_image_filter_commands[] = {

    { ngx_string("image_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_image_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_jpeg_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_jpeg_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_webp_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_webp_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_sharpen"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_sharpen,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_transparency"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, transparency),
      NULL },

    { ngx_string("image_filter_interlace"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, interlace),
      NULL },

    { ngx_string("image_filter_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, buffer_size),
      NULL },
    { ngx_string("image_filter_watermark_height_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, watermark_height_from),
      NULL },
    { ngx_string("image_filter_watermark_width_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, watermark_width_from),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_image_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_image_filter_init,            /* postconfiguration */

    ngx_http_image_filter_main_create_conf,/* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_image_filter_create_conf,     /* create location configuration */
    ngx_http_image_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_image_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_image_filter_module_ctx,     /* module context */
    ngx_http_image_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_str_t  ngx_http_image_types[] = {
    ngx_string("image/jpeg"),
    ngx_string("image/gif"),
    ngx_string("image/png"),
    ngx_string("image/webp")
};


static ngx_int_t
ngx_http_image_header_filter(ngx_http_request_t *r)
{
    off_t                          len;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx) {
        ngx_http_set_ctx(r, NULL, ngx_http_image_filter_module);
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

    if (conf->filter == NGX_HTTP_IMAGE_OFF) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: multipart/x-mixed-replace response");

        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_image_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_image_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: too big response: %O", len);

        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {
        ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_image_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    ngx_str_t                     *ct;
    ngx_chain_t                    out;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "image filter");

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case NGX_HTTP_IMAGE_START:

        ctx->type = ngx_http_image_test(r, in);

        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        if (ctx->type == NGX_HTTP_IMAGE_NONE) {

            if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
                out.buf = ngx_http_image_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = NGX_HTTP_IMAGE_DONE;

                    return ngx_http_image_send(r, ctx, &out);
                }
            }

            /*return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);*/
        }

        /* override content type */

        ct = &ngx_http_image_types[ctx->type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == NGX_HTTP_IMAGE_TEST || ctx->type == NGX_HTTP_IMAGE_NONE) {
            ctx->phase = NGX_HTTP_IMAGE_PASS;

            return ngx_http_image_send(r, ctx, in);
        }

        ctx->phase = NGX_HTTP_IMAGE_READ;

        /* fall through */

    case NGX_HTTP_IMAGE_READ:

        rc = ngx_http_image_read(r, in);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case NGX_HTTP_IMAGE_PROCESS:

        out.buf = ngx_http_image_process(r);

        if (out.buf == NULL) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_IMAGE_PASS;

        return ngx_http_image_send(r, ctx, &out);

    case NGX_HTTP_IMAGE_PASS:

        return ngx_http_next_body_filter(r, in);

    default: /* NGX_HTTP_IMAGE_DONE */

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}


static ngx_int_t
ngx_http_image_send(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_IMAGE_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}


static ngx_uint_t
ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return NGX_HTTP_IMAGE_NONE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return NGX_HTTP_IMAGE_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return NGX_HTTP_IMAGE_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return NGX_HTTP_IMAGE_PNG;

    } else if (p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F'
               && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P')
    {
        /* WebP */

        return NGX_HTTP_IMAGE_WEBP;
    }

    return NGX_HTTP_IMAGE_NONE;
}


static ngx_int_t
ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_image_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx->image == NULL) {
        ctx->image = ngx_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return NGX_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "image buf: %uz", size);

        rest = ctx->image + ctx->length - p;

        if (size > rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "image filter: too big response");
            return NGX_ERROR;
        }

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return NGX_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= NGX_HTTP_IMAGE_BUFFERED;

    return NGX_AGAIN;
}


static ngx_buf_t *
ngx_http_image_process(ngx_http_request_t *r)
{
    int                            matches, sl;
    ngx_int_t                      rc;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;
    ngx_http_image_filter_main_conf_t  *main_conf;

    r->connection->buffered &= ~NGX_HTTP_IMAGE_BUFFERED;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    rc = ngx_http_image_size(r, ctx);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
    main_conf = ngx_http_get_module_main_conf(r, ngx_http_image_filter_module);

    /* 解析请求参数 x-image-process */
    int captures [(1 + main_conf->image_process_captures)* 3];
    matches = ngx_regex_exec(main_conf->image_process_re, &r->args, captures, (1 + main_conf->image_process_captures) * 3);
    if (matches >= 0) {
        ngx_str_t   image_process_arg = ngx_null_string;

        /* all captures */
        for (sl = 0; sl < matches * 2; sl += 2) {
            image_process_arg.data = r->args.data + captures[sl];
            image_process_arg.len = captures[sl + 1] - captures[sl];
        }
        sl = image_process_arg.len - 16;
        char *token, *temp_arg, *pSave = NULL;;
        const char split_char[2] = ",/";
        temp_arg = ngx_pcalloc(r->pool, sl + 1);

        ngx_memcpy(temp_arg, (char *)image_process_arg.data + 16, sl);
        token = strtok_r(temp_arg, split_char, &pSave);
        // 控制最大循环次数
        while( token != NULL && sl ) {
            if(ngx_strcmp(token, "watermark") == 0){
                conf->filter = NGX_HTTP_IMAGE_WATERMARK;
                break;
            } else if (ngx_strcmp(token, "resize") == 0){
                conf->filter = NGX_HTTP_IMAGE_RESIZE;
                break;
            }
            sl--;
        }
    }

    if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
        return ngx_http_image_json(r, rc == NGX_OK ? ctx : NULL);
    }

    ctx->angle = ngx_http_image_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

	    return ngx_http_image_resize(r, ctx);
	}

	if (conf->filter == NGX_HTTP_IMAGE_WATERMARK) {
	    return ngx_http_image_resize(r, ctx);
	}

	ctx->max_width = ngx_http_image_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = ngx_http_image_filter_get_value(r, conf->hcv,
                                                      conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    if (rc == NGX_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force)
    {
        return ngx_http_image_asis(r, ctx);
    }

    return ngx_http_image_resize(r, ctx);
}


static ngx_buf_t *
ngx_http_image_json(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    size_t      len;
    ngx_buf_t  *b;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    ngx_http_clean_header(r);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        ngx_http_image_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
          + 2 * NGX_SIZE_T_LEN;

    b->pos = ngx_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = ngx_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          ngx_http_image_types[ctx->type - 1].data + 6);

    ngx_http_image_length(r, b);

    return b;
}

static ngx_buf_t *
ngx_http_image_asis(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_image_length(r, b);

    return b;
}


static void
ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static ngx_int_t
ngx_http_image_size(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    u_char      *p, *last;
    size_t       len, app;
    ngx_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case NGX_HTTP_IMAGE_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
                     || *p == 0xc9 || *p == 0xca || *p == 0xcb)
                    && (width == 0 || height == 0))
                {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[1], p[2]);

                len = p[1] * 256 + p[2];

                if (*p >= 0xe1 && *p <= 0xef) {
                    /* application data, e.g., EXIF, Adobe XMP, etc. */
                    app += len;
                }

                p += len;

                continue;
            }

            p++;
        }

        if (width == 0 || height == 0) {
            return NGX_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "app data size: %uz", app);
        }

        break;

    case NGX_HTTP_IMAGE_GIF:

        if (ctx->length < 10) {
            return NGX_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case NGX_HTTP_IMAGE_PNG:

        if (ctx->length < 24) {
            return NGX_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case NGX_HTTP_IMAGE_WEBP:

        if (ctx->length < 30) {
            return NGX_DECLINED;
        }

        if (p[12] != 'V' || p[13] != 'P' || p[14] != '8') {
            return NGX_DECLINED;
        }

        switch (p[15]) {

        case ' ':
            if (p[20] & 1) {
                /* not a key frame */
                return NGX_DECLINED;
            }

            if (p[23] != 0x9d || p[24] != 0x01 || p[25] != 0x2a) {
                /* invalid start code */
                return NGX_DECLINED;
            }

            width = (p[26] | p[27] << 8) & 0x3fff;
            height = (p[28] | p[29] << 8) & 0x3fff;

            break;

        case 'L':
            if (p[20] != 0x2f) {
                /* invalid signature */
                return NGX_DECLINED;
            }

            width = ((p[21] | p[22] << 8) & 0x3fff) + 1;
            height = ((p[22] >> 6 | p[23] << 2 | p[24] << 10) & 0x3fff) + 1;

            break;

        case 'X':
            width = (p[24] | p[25] << 8 | p[26] << 16) + 1;
            height = (p[27] | p[28] << 8 | p[29] << 16) + 1;
            break;

        default:
            return NGX_DECLINED;
        }

        break;

    default:

        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image size: %d x %d", (int) width, (int) height);

    ctx->width = width;
    ctx->height = height;

    return NGX_OK;
}


static ngx_buf_t *
ngx_http_image_resize(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
                                   colors, palette, transparent, sharpen,
                                   red, green, blue, t, sl, matches, tx, ty;
    u_char                        *out;
    ngx_buf_t                     *b;
    ngx_uint_t                     resize;
    gdImagePtr                     src, dst;
    ngx_pool_cleanup_t            *cln;
    ngx_http_image_filter_conf_t  *conf;
    ngx_http_image_filter_main_conf_t  *main_conf;
    image_watermark_args watermark_arg = {ngx_null_string, ngx_null_string, 40, ngx_string("d3F5LXplbmhlaQ"), ngx_string("000000"), ngx_string("br"), 10, 10, 100, 0, 0, 100};

    src = ngx_http_image_source(r, ctx);

    if (src == NULL) {
        return NULL;
    }

    sx = gdImageSX(src);
    sy = gdImageSY(src);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
    main_conf = ngx_http_get_module_main_conf(r, ngx_http_image_filter_module);

    /* 解析请求参数 x-image-process */
    int captures [(1 + main_conf->image_process_captures)* 3];
    matches = ngx_regex_exec(main_conf->image_process_re, &r->args, captures, (1 + main_conf->image_process_captures) * 3);
    if (matches >= 0) {
        /* string matches expression */
        ngx_str_t   image_process_arg = ngx_null_string;

        /* all captures */
        for (t = 0; t < matches * 2; t += 2) {
            image_process_arg.data = r->args.data + captures[t];
            image_process_arg.len = captures[t + 1] - captures[t];
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "image_process argument: %V", &image_process_arg);
        t = sl = image_process_arg.len - 16;
        char *token, *temp_arg, *pSave = NULL;;
        const char split_char[2] = ",/";
        temp_arg = ngx_pcalloc(r->pool, sl + 1);

        ngx_memcpy(temp_arg, (char *)image_process_arg.data + 16, sl);
        token = strtok_r(temp_arg, split_char, &pSave);

        while( token != NULL && t ) {
            if (ngx_strcmp(token, "image") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                watermark_arg.image.len = ngx_min(ngx_strlen(token), 64);
                watermark_arg.image.data = (u_char *)token;
            } else if (ngx_strcmp(token, "text") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                watermark_arg.text.len = ngx_min(ngx_strlen(token), 64);
                watermark_arg.text.data = (u_char *)token;
            } else if (ngx_strcmp(token, "size") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                watermark_arg.size = ngx_atoi((u_char *)token, ngx_strnlen((u_char *)token, 3));
            } else if (ngx_strcmp(token, "type") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                watermark_arg.type.len = ngx_min(ngx_strlen(token), 32);
                watermark_arg.type.data = (u_char *)token;
            } else if (ngx_strcmp(token, "color") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                watermark_arg.color.len = ngx_strlen(token);
                if(ngx_strlen(token) == 6){
                    watermark_arg.color.data = (u_char *)token;
                }
            } else if (ngx_strcmp(token, "g") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                watermark_arg.g.len = ngx_strlen(token);
                watermark_arg.g.data = (u_char *)token;
            } else if (ngx_strcmp(token, "t") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                sl = ngx_atoi((u_char *)token, ngx_strlen(token));
                if (sl < 0 || sl > 100) {
                    sl = 100;
                }
                watermark_arg.t = sl;
            } else if (ngx_strcmp(token, "x") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                sl = ngx_atoi((u_char *)token, ngx_strlen(token));
                if (sl < 0 || sl > 4096) {
                    sl = 10;
                }
                watermark_arg.x = sl;
            } else if (ngx_strcmp(token, "y") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                sl = ngx_atoi((u_char *)token, ngx_strlen(token));
                if (sl < 0 || sl > 4096) {
                    sl = 10;
                }
                watermark_arg.y = sl;
            } else if (ngx_strcmp(token, "fill") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                watermark_arg.fill = ngx_atoi((u_char *)token, ngx_strlen(token));
            } else if (ngx_strcmp(token, "rotate") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                sl = ngx_atoi((u_char *)token, ngx_strlen(token));
                if (sl < 0 || sl > 360) {
                    sl = 360;
                }
                watermark_arg.rotate = 360 - sl;
            } else if (ngx_strcmp(token, "interval") == 0) {
                token = strtok_r(NULL, split_char, &pSave);
                sl = ngx_atoi((u_char *)token, ngx_strlen(token));
                if (sl < 0 || sl > 1000) {
                    sl = 100;
                }
                watermark_arg.interval = sl;
            }

            if (token != NULL) {
                token = strtok_r(NULL, split_char, &pSave);
            }
            t--;
        }
    }

    if (!ctx->force
        && ctx->angle == 0
        && (ngx_uint_t) sx <= ctx->max_width
        && (ngx_uint_t) sy <= ctx->max_height)
    {
        gdImageDestroy(src);
        return ngx_http_image_asis(r, ctx);
    }

    colors = gdImageColorsTotal(src);

    if (colors && conf->transparency) {
        transparent = gdImageGetTransparent(src);

        if (transparent != -1) {
            palette = colors;
            red = gdImageRed(src, transparent);
            green = gdImageGreen(src, transparent);
            blue = gdImageBlue(src, transparent);

            goto transparent;
        }
    }

    palette = 0;
    transparent = -1;
    red = 0;
    green = 0;
    blue = 0;

transparent:

    gdImageColorTransparent(src, -1);

    dx = sx;
    dy = sy;

    if (conf->filter == NGX_HTTP_IMAGE_RESIZE) {

        if ((ngx_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }

        resize = 1;

    } else if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {

        resize = 0;

    } else if (conf->filter == NGX_HTTP_IMAGE_WATERMARK) {
        resize = 0;
    } else { /* NGX_HTTP_IMAGE_CROP */

        resize = 0;

        if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((ngx_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((ngx_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }

    if (resize) {
        dst = ngx_http_image_new(r, dx, dy, palette);
        if (dst == NULL) {
            gdImageDestroy(src);
            return NULL;
        }

        if (colors == 0) {
            gdImageSaveAlpha(dst, 1);
            gdImageAlphaBlending(dst, 0);
        }

        gdImageCopyResampled(dst, src, 0, 0, 0, 0, dx, dy, sx, sy);

        if (colors) {
            gdImageTrueColorToPalette(dst, 1, 256);
        }

        gdImageDestroy(src);

    } else {
        dst = src;
    }

    if (ctx->angle) {
        src = dst;

        ax = (dx % 2 == 0) ? 1 : 0;
        ay = (dy % 2 == 0) ? 1 : 0;

        switch (ctx->angle) {

        case 90:
        case 270:
            dst = ngx_http_image_new(r, dy, dx, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            if (ctx->angle == 90) {
                ox = dy / 2 + ay;
                oy = dx / 2 - ax;

            } else {
                ox = dy / 2 - ay;
                oy = dx / 2 + ax;
            }

            gdImageCopyRotated(dst, src, ox, oy, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);

            t = dx;
            dx = dy;
            dy = t;
            break;

        case 180:
            dst = ngx_http_image_new(r, dx, dy, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            gdImageCopyRotated(dst, src, dx / 2 - ax, dy / 2 - ay, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);
            break;
        }
    }

    if (conf->filter == NGX_HTTP_IMAGE_CROP) {

        src = dst;

        if ((ngx_uint_t) dx > ctx->max_width) {
            ox = dx - ctx->max_width;

        } else {
            ox = 0;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            oy = dy - ctx->max_height;

        } else {
            oy = 0;
        }

        if (ox || oy) {

            dst = ngx_http_image_new(r, dx - ox, dy - oy, colors);

            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }

            ox /= 2;
            oy /= 2;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "image crop: %d x %d @ %d x %d",
                           dx, dy, ox, oy);

            if (colors == 0) {
                gdImageSaveAlpha(dst, 1);
                gdImageAlphaBlending(dst, 0);
            }

            gdImageCopy(dst, src, 0, 0, ox, oy, dx - ox, dy - oy);

            if (colors) {
                gdImageTrueColorToPalette(dst, 1, 256);
            }

            gdImageDestroy(src);
        }
    }

    if (transparent != -1 && colors) {
        gdImageColorTransparent(dst, gdImageColorExact(dst, red, green, blue));
    }

    if (conf->filter == NGX_HTTP_IMAGE_WATERMARK) {
        int min_w, min_h, tw=0, th=0, psx, psy;

        min_w=dx;
        min_h=dy;

        if (!min_w || min_w < 0) {
            min_w=ctx->max_width;
        }

        if (!min_h || min_h < 0) {
            min_h=ctx->max_height;
        }

        if ( min_w >= conf->watermark_width_from &&
              min_h >= conf->watermark_height_from){
            char font_path[50];
            gdImagePtr watermark=NULL, watermark_mix, white, white_mix;
            ngx_int_t wdx = 0, wdy = 0;
            if (watermark_arg.image.len) {
                ngx_str_t image_path;
                image_path.len = ngx_base64_decoded_length(watermark_arg.image.len);
                image_path.data = ngx_pcalloc(r->pool, image_path.len + 1);
                ngx_decode_base64url(&image_path, &watermark_arg.image);
                sprintf(font_path, "%s/%s", NGX_IMAGE_PATH, image_path.data);
                FILE *watermark_file = fopen((const char *)font_path, "r");
                if (watermark_file) {
                    watermark = gdImageCreateFromPng(watermark_file);
                    if(watermark != NULL) {
                        tw = watermark->sx;
                        th = watermark->sy;
                        psx = psy = 0;
                    } else {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "watermark file '%V' is not PNG", &image_path);
                    }

                    fclose(watermark_file);
                } else {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "watermark file '%V' not found", &image_path);
                }
            } else if (watermark_arg.text.len) {
                u_char lower_key[watermark_arg.type.len];
                ngx_str_t water_text, *font_real_path;
                ngx_uint_t k = ngx_hash_key_lc(watermark_arg.type.data, watermark_arg.type.len);
                ngx_strlow(lower_key, watermark_arg.type.data, watermark_arg.type.len);
                font_real_path = (ngx_str_t *)ngx_hash_find(&main_conf->font_hash, k, lower_key, watermark_arg.type.len);
                if (font_real_path == NULL) {
                    font_real_path = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
                    ngx_str_set(font_real_path, "wqy-zenhei.ttc");
                }
                water_text.len = ngx_base64_decoded_length(watermark_arg.text.len);
                water_text.data = ngx_pcalloc(r->pool, water_text.len + 1);
                ngx_decode_base64url(&water_text, &watermark_arg.text);
                sprintf(font_path, "%s/%s", NGX_FONT_PATH, font_real_path->data);

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "text '%V', font_real_path '%s' , corlor '%V'", &water_text, font_path, &watermark_arg.color);
                FILE *water_font_file = fopen((const char *)font_path, "r");
                if (water_font_file) {//如果水印字体存在
                	int water_color, R,G,B;
                	char R_str[3],G_str[3],B_str[3];
                	int brect[8];
                	sprintf(R_str,"%.*s",2,watermark_arg.color.data);
                	sprintf(G_str,"%.*s",2,watermark_arg.color.data+2);
                	sprintf(B_str,"%.*s",2,watermark_arg.color.data+4);
                	sscanf(R_str,"%x",&R);
                	sscanf(G_str,"%x",&G);
                	sscanf(B_str,"%x",&B);
                	double angle = ((double)watermark_arg.rotate/180)*M_PI;
                	gdImageStringFT(NULL, &brect[0], 0, font_path, watermark_arg.size, angle, 0, 0, (char *)water_text.data);
                	// 测算水印图片实际宽高
                	tw = ngx_max(ngx_abs(brect[4]-brect[0]), ngx_abs(brect[6]-brect[2]));
                	th = ngx_max(ngx_abs(brect[5]-brect[1]), ngx_abs(brect[7]-brect[3]));
                	if (watermark_arg.rotate >= 0 && watermark_arg.rotate <= 90) {
                        psx = ngx_abs(brect[6]);
                        psy = ngx_abs(brect[5]);
                	} else if (watermark_arg.rotate > 90 && watermark_arg.rotate <= 180) {
                        psx = ngx_abs(brect[4]);
                        psy = ngx_abs(brect[3]);
                	} else if (watermark_arg.rotate > 180 && watermark_arg.rotate <= 270) {
                        psx = ngx_abs(brect[2]);
                        psy = ngx_abs(brect[1]);
                    } else {
                        psx = ngx_abs(brect[0]);
                        psy = ngx_abs(brect[7]);
                    }

                    if (watermark_arg.fill) {
                        watermark = gdImageCreate(dst->sx, dst->sy);
                        gdImageColorAllocateAlpha(watermark, R, G, B, gdAlphaTransparent);
                        gdImageColorTransparent(watermark, 0);
                        water_color = gdImageColorAllocate(watermark, R, G, B);
                        for (tx=10; tx < dx;  tx+= (tw + watermark_arg.interval)){
                            for(ty=ngx_abs(brect[1]-brect[7]); ty < dy + watermark_arg.interval; ty+= (th + watermark_arg.interval)){
                                gdImageStringFT(watermark, &brect[0], water_color, font_path, watermark_arg.size, angle, tx, ty, (char *)water_text.data);
                            }
                        }
                    } else {
                        watermark = gdImageCreate(tw, th);
                        gdImageColorAllocateAlpha(watermark, R, G, B, gdAlphaTransparent);
                        gdImageColorTransparent(watermark, 0);
                        water_color = gdImageColorAllocate(watermark, R, G, B);
                        gdImageStringFT(watermark, &brect[0], water_color, font_path, watermark_arg.size, angle, psx, psy, (char *)water_text.data);
                    }
                    fclose(water_font_file);
                }
            }

            // 计算水印图片坐标位置
            if(watermark_arg.g.len && !watermark_arg.fill){
                // 混合后水印坐标计算以水印图片左上角为起点
                if (ngx_strcmp(watermark_arg.g.data, "br") == 0) {
                    wdx = (int)dst->sx - tw - watermark_arg.x;
                    wdy = (int)dst->sy - th - watermark_arg.y;
                } else if (ngx_strcmp(watermark_arg.g.data, "tl") == 0) {
                    wdx = watermark_arg.x;
                    wdy = watermark_arg.y;
                } else if (ngx_strcmp(watermark_arg.g.data, "tr") == 0) {
                    wdx = (int)dst->sx - tw - watermark_arg.x;
                    wdy = watermark_arg.y;
                } else if (ngx_strcmp(watermark_arg.g.data, "bl") == 0) {
                    wdx = watermark_arg.x;
                    wdy = (int)dst->sy - th - watermark_arg.y;
                }else if (ngx_strcmp(watermark_arg.g.data, "top") == 0) {
                    wdx = (int)dst->sx/2 - (int)tw/2;
                    wdy = watermark_arg.y;
                }else if (ngx_strcmp(watermark_arg.g.data, "bottom") == 0) {
                    wdx = (int)dst->sx/2 - (int)tw/2;
                    wdy = (int)dst->sy - th - watermark_arg.y;
                }else if (ngx_strcmp(watermark_arg.g.data, "left") == 0) {
                    wdx = watermark_arg.x;
                    wdy = (int)dst->sy/2 - (int)th/2;
                }else if (ngx_strcmp(watermark_arg.g.data, "right") == 0) {
                    wdx = (int)dst->sx - tw - watermark_arg.x;
                    wdy = (int)dst->sy/2 - (int)th/2;
                }else if (ngx_strcmp(watermark_arg.g.data, "center") == 0) {
                    wdx = (int)dst->sx/2 - (int)tw/2;
                    wdy = (int)dst->sy/2 - (int)th/2;
                }else if (ngx_strcmp(watermark_arg.g.data, "random") == 0) {
                    ngx_int_t randomBit = rand() & 1;
                    if (randomBit) {
                        wdx = ((int)dst->sx/2 - (int)tw/2) - (int)((double)rand() / ((double)RAND_MAX + 1) * 15);
                        wdy = ((int)dst->sy/2 - (int)th/2) + (int)((double)rand() / ((double)RAND_MAX + 1) * 15);
                    } else {
                        wdx = ((int)dst->sx/2 - (int)tw/2) + (int)((double)rand() / ((double)RAND_MAX + 1) * 15);
                        wdy = ((int)dst->sy/2 - (int)th/2) - (int)((double)rand() / ((double)RAND_MAX + 1) * 15);
                    }
                } else { // 默认br
                    wdx = (int)dst->sx - tw - watermark_arg.x;
                    wdy = (int)dst->sy - th - watermark_arg.y;
                }
            }
            if (watermark != NULL){
                watermark_mix = gdImageCreateTrueColor(watermark->sx, watermark->sy);
                // WorkAround on transparent source, fill background to white
                if (ctx->type == NGX_HTTP_IMAGE_GIF || ctx->type == NGX_HTTP_IMAGE_PNG) {
                    white = gdImageCreateTrueColor(dst->sx, dst->sy);
                    white_mix = gdImageCreateTrueColor(dst->sx, dst->sy);
                    gdImageFill(white,0,0,gdImageColorAllocate(white,255,255,255));
                    gdImageCopy(white_mix, white, 0, 0, 0, 0, white_mix->sx, white_mix->sy);
                    gdImageCopy(white_mix, dst, 0, 0, 0, 0, white_mix->sx, white_mix->sy);
                    gdImageCopyMerge(white, white_mix, 0, 0, 0, 0, white->sx, white->sy, 100);
                    gdImageDestroy(dst);
                    gdImageDestroy(white_mix);
                    dst=white;
                }
                gdImageCopy(watermark_mix, dst, 0, 0, wdx, wdy, watermark->sx, watermark->sy);
                gdImageCopy(watermark_mix, watermark, 0, 0, 0, 0, watermark->sx, watermark->sy);
                gdImageCopyMerge(dst, watermark_mix, wdx, wdy, 0, 0, watermark->sx, watermark->sy, watermark_arg.t);
                gdImageDestroy(watermark_mix);
                gdImageDestroy(watermark);
            }

        }else{
            if (conf->filter == NGX_HTTP_IMAGE_WATERMARK)
            {
                gdImageDestroy(src);
                return ngx_http_image_asis(r, ctx);
            }
        }
    }


    sharpen = ngx_http_image_filter_get_value(r, conf->shcv, conf->sharpen);
    if (sharpen > 0) {
        gdImageSharpen(dst, sharpen);
    }

    gdImageInterlace(dst, (int) conf->interlace);

    out = ngx_http_image_out(r, ctx->type, dst, &size);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image: %d x %d %d", sx, sy, colors);

    gdImageDestroy(dst);
    ngx_pfree(r->pool, ctx->image);

    if (out == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        gdFree(out);
        return NULL;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        gdFree(out);
        return NULL;
    }

    cln->handler = ngx_http_image_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_image_length(r, b);
    ngx_http_weak_etag(r);

    return b;
}


static gdImagePtr
ngx_http_image_source(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    char        *failed;
    gdImagePtr   img;

    img = NULL;

    switch (ctx->type) {

    case NGX_HTTP_IMAGE_JPEG:
        img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromJpegPtr() failed";
        break;

    case NGX_HTTP_IMAGE_GIF:
        img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromGifPtr() failed";
        break;

    case NGX_HTTP_IMAGE_PNG:
        img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromPngPtr() failed";
        break;

    case NGX_HTTP_IMAGE_WEBP:
#if (NGX_HAVE_GD_WEBP)
        img = gdImageCreateFromWebpPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromWebpPtr() failed";
#else
        failed = "nginx was built without GD WebP support";
#endif
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (img == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return img;
}


static gdImagePtr
ngx_http_image_new(ngx_http_request_t *r, int w, int h, int colors)
{
    gdImagePtr  img;

    if (colors == 0) {
        img = gdImageCreateTrueColor(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "gdImageCreateTrueColor() failed");
            return NULL;
        }

    } else {
        img = gdImageCreate(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "gdImageCreate() failed");
            return NULL;
        }
    }

    return img;
}


static u_char *
ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type, gdImagePtr img,
    int *size)
{
    char                          *failed;
    u_char                        *out;
    ngx_int_t                      q;
    ngx_http_image_filter_conf_t  *conf;

    out = NULL;

    switch (type) {

    case NGX_HTTP_IMAGE_JPEG:
        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        q = ngx_http_image_filter_get_value(r, conf->jqcv, conf->jpeg_quality);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageJpegPtr(img, size, q);
        failed = "gdImageJpegPtr() failed";
        break;

    case NGX_HTTP_IMAGE_GIF:
        out = gdImageGifPtr(img, size);
        failed = "gdImageGifPtr() failed";
        break;

    case NGX_HTTP_IMAGE_PNG:
        out = gdImagePngPtr(img, size);
        failed = "gdImagePngPtr() failed";
        break;

    case NGX_HTTP_IMAGE_WEBP:
#if (NGX_HAVE_GD_WEBP)
        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        q = ngx_http_image_filter_get_value(r, conf->wqcv, conf->webp_quality);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageWebpPtrEx(img, size, q);
        failed = "gdImageWebpPtrEx() failed";
#else
        failed = "nginx was built without GD WebP support";
#endif
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (out == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}


static void
ngx_http_image_cleanup(void *data)
{
    gdFree(data);
}


static ngx_uint_t
ngx_http_image_filter_get_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v)
{
    ngx_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
        return 0;
    }

    return ngx_http_image_filter_value(&val);
}


static ngx_uint_t
ngx_http_image_filter_value(ngx_str_t *value)
{
    ngx_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (ngx_uint_t) -1;
    }

    n = ngx_atoi(value->data, value->len);

    if (n > 0) {
        return (ngx_uint_t) n;
    }

    return 0;
}

// 初始化字体配置信息
static void *
ngx_http_image_filter_main_create_conf(ngx_conf_t * cf)
{
    ngx_http_image_filter_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_image_filter_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    // 读取font目录并解析文件名称
    const char ch = '.';
    size_t real_len, suffix_len, font_name_len;
    DIR *dir = NULL;
    struct dirent *entry;

    // font hash表
    ngx_hash_key_t   *font_type;
    ngx_array_t *key_array;

    if ((dir = opendir(NGX_FONT_PATH)) == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "水印字体文件目录：%s 不存在", NGX_FONT_PATH);
        return NGX_CONF_ERROR;
    } else {
        key_array = ngx_array_create(cf->pool, 8, sizeof(ngx_hash_key_t));
        while ((entry = readdir(dir)) != NULL) {
            // 只有当文件类型为普通文件时
            if (entry->d_type == DT_REG){
                ngx_str_t font_file_name;
                real_len = ngx_strlen(entry->d_name);
                suffix_len = ngx_strlen(strrchr(entry->d_name, ch));
				font_name_len = real_len - suffix_len;
				font_file_name.len = font_name_len;
				font_file_name.data = ngx_pcalloc(cf->pool, real_len-suffix_len);
				ngx_memcpy(font_file_name.data, entry->d_name, real_len-suffix_len);

				ngx_str_t encode_name;
				encode_name.len = ngx_base64_encoded_length(font_name_len);
				encode_name.data = ngx_pcalloc(cf->pool, encode_name.len+1);
                ngx_encode_base64url(&encode_name, &font_file_name);
                ngx_pfree(cf->pool, &font_file_name);

                font_type = ngx_array_push(key_array);
                if (font_type == NULL) {
                    return NGX_CONF_ERROR;
                }

                ngx_str_t *font_real_path = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
                font_real_path->len = real_len;
                font_real_path->data = ngx_pcalloc(cf->pool, real_len+1);
                ngx_memcpy(font_real_path->data, entry->d_name, real_len);

                font_type->key = encode_name;
                font_type->key_hash = ngx_hash_key_lc(encode_name.data, encode_name.len);
                font_type->value = font_real_path;
            }
        }
        closedir(dir);
    }

    ngx_hash_t       font_hash;
    ngx_hash_init_t  hash_init;

    hash_init.hash = &font_hash;
    hash_init.key = ngx_hash_key_lc;
    hash_init.max_size = 16;
    hash_init.bucket_size = 64;
    hash_init.name = "font_hash";
    hash_init.pool = cf->pool;
    hash_init.temp_pool = NULL;
    if(key_array->nelts < 1){
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "水印字体加载失败，文件目录：%s", NGX_FONT_PATH);
        return NGX_CONF_ERROR;
    }
    ngx_hash_init(&hash_init, key_array->elts, key_array->nelts);

    conf->font_hash = font_hash;

#if (NGX_PCRE)
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t  args_pattern = ngx_string("[^&]+");

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = args_pattern;
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    /* rc.options are passed as is to pcre_compile() */

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_CONF_ERROR;
    }
    conf->args_re = rc.regex;
    conf->args_captures = rc.captures;

    ngx_str_t  image_process_pattern = ngx_string("x-image-process=[^&]*");

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = image_process_pattern;
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    /* rc.options are passed as is to pcre_compile() */

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_CONF_ERROR;
    }
    conf->image_process_re = rc.regex;
    conf->image_process_captures = rc.captures;

    ngx_str_t  value_pattern = ngx_string("(?<==)[^&]*");

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = value_pattern;
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    /* rc.options are passed as is to pcre_compile() */

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_CONF_ERROR;
    }
    conf->value_re = rc.regex;
    conf->value_captures = rc.captures;
#endif
    return conf;
}

static void *
ngx_http_image_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_image_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_image_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->width = 0;
     *     conf->height = 0;
     *     conf->angle = 0;
     *     conf->wcv = NULL;
     *     conf->hcv = NULL;
     *     conf->acv = NULL;
     *     conf->jqcv = NULL;
     *     conf->wqcv = NULL;
     *     conf->shcv = NULL;
     */

    conf->filter = NGX_CONF_UNSET_UINT;
    conf->jpeg_quality = NGX_CONF_UNSET_UINT;
    conf->webp_quality = NGX_CONF_UNSET_UINT;
    conf->sharpen = NGX_CONF_UNSET_UINT;
    conf->transparency = NGX_CONF_UNSET;
    conf->interlace = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;

    conf->watermark_width_from = NGX_CONF_UNSET_UINT;
    conf->watermark_height_from = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_image_filter_conf_t *prev = parent;
    ngx_http_image_filter_conf_t *conf = child;

    if (conf->filter == NGX_CONF_UNSET_UINT) {

        if (prev->filter == NGX_CONF_UNSET_UINT) {
            conf->filter = NGX_HTTP_IMAGE_OFF;

        } else {
            conf->filter = prev->filter;
            conf->width = prev->width;
            conf->height = prev->height;
            conf->angle = prev->angle;
            conf->wcv = prev->wcv;
            conf->hcv = prev->hcv;
            conf->acv = prev->acv;
        }
    }

    if (conf->jpeg_quality == NGX_CONF_UNSET_UINT) {

        /* 75 is libjpeg default quality */
        ngx_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);

        if (conf->jqcv == NULL) {
            conf->jqcv = prev->jqcv;
        }
    }

    if (conf->webp_quality == NGX_CONF_UNSET_UINT) {

        /* 80 is libwebp default quality */
        ngx_conf_merge_uint_value(conf->webp_quality, prev->webp_quality, 80);

        if (conf->wqcv == NULL) {
            conf->wqcv = prev->wqcv;
        }
    }

    if (conf->sharpen == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);

        if (conf->shcv == NULL) {
            conf->shcv = prev->shcv;
        }
    }

    ngx_conf_merge_value(conf->transparency, prev->transparency, 1);

    ngx_conf_merge_value(conf->interlace, prev->interlace, 0);

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);
    
    ngx_conf_merge_value(conf->watermark_height_from, prev->watermark_height_from, 0);
    ngx_conf_merge_value(conf->watermark_width_from, prev->watermark_height_from, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_uint_t                         i;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[i].data, "off") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_OFF;

        } else if (ngx_strcmp(value[i].data, "test") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_TEST;

        } else if (ngx_strcmp(value[i].data, "size") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_SIZE;

        } else if (ngx_strcmp(value[i].data, "watermark") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_WATERMARK;
        } else {
            goto failed;
        }

        return NGX_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (ngx_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != NGX_HTTP_IMAGE_RESIZE
                && imcf->filter != NGX_HTTP_IMAGE_CROP)
            {
                imcf->filter = NGX_HTTP_IMAGE_ROTATE;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = ngx_http_image_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (ngx_uint_t) n;

            } else {
                imcf->acv = ngx_palloc(cf->pool,
                                       sizeof(ngx_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return NGX_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return NGX_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (ngx_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = NGX_HTTP_IMAGE_RESIZE;

    } else if (ngx_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = NGX_HTTP_IMAGE_CROP;
    } else if (ngx_strcmp(value[i].data, "watermark") == 0) {
        imcf->filter = NGX_HTTP_IMAGE_WATERMARK;
    } else {
        goto failed;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (ngx_uint_t) n;

    } else {
        imcf->wcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (ngx_uint_t) n;

    } else {
        imcf->hcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return NGX_CONF_OK;

failed:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_image_filter_jpeg_quality(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[1]);

        if (n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->jpeg_quality = (ngx_uint_t) n;

    } else {
        imcf->jqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->jqcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->jqcv = cv;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_image_filter_webp_quality(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[1]);

        if (n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->webp_quality = (ngx_uint_t) n;

    } else {
        imcf->wqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wqcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->wqcv = cv;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_image_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[1]);

        if (n < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->sharpen = (ngx_uint_t) n;

    } else {
        imcf->shcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->shcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->shcv = cv;
    }

    return NGX_CONF_OK;
}

// 控制 imagefilter 位于请求时间段
static ngx_int_t
ngx_http_image_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_image_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_image_body_filter;

    return NGX_OK;
}
