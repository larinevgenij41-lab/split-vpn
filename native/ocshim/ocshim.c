/*
 * ocshim — прослойка между libopenconnect и управляемым кодом SplitVpn.
 *
 * Зачем нужна:
 *  - колбэк прогресса libopenconnect вариативный (printf-формат), .NET его принять не может;
 *  - результат getaddrinfo библиотека освобождает через freeaddrinfo, поэтому структуру
 *    должен выделять настоящий getaddrinfo, а не управляемый код.
 *
 * Все колбэки библиотеки получают cbdata = struct ocshim_ctx*, прослойка пересылает
 * их в управляемые указатели на функции вместе с непрозрачным priv.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openconnect.h>

typedef int (*ocshim_validate_fn)(void *priv, const char *reason);
typedef int (*ocshim_form_fn)(void *priv, struct oc_auth_form *form);
typedef void (*ocshim_log_fn)(void *priv, int level, const char *message);
typedef int (*ocshim_webview_fn)(void *priv, const char *uri);
typedef int (*ocshim_resolve_fn)(void *priv, const char *node, char *address, int address_len);
typedef void (*ocshim_event_fn)(void *priv);
typedef void (*ocshim_stats_fn)(void *priv, const struct oc_stats *stats);

struct ocshim_callbacks {
	ocshim_validate_fn validate;
	ocshim_form_fn form;
	ocshim_log_fn log;
	ocshim_webview_fn webview;
	ocshim_resolve_fn resolve; /* может быть NULL */
	ocshim_event_fn setup_tun;
	ocshim_event_fn reconnected;
	ocshim_stats_fn stats;
};

struct ocshim_ctx {
	struct ocshim_callbacks cb;
	void *priv;
	struct openconnect_info *vpninfo;
};

static int shim_validate(void *data, const char *reason)
{
	struct ocshim_ctx *ctx = data;
	return ctx->cb.validate ? ctx->cb.validate(ctx->priv, reason) : -1;
}

static int shim_form(void *data, struct oc_auth_form *form)
{
	struct ocshim_ctx *ctx = data;
	return ctx->cb.form ? ctx->cb.form(ctx->priv, form) : OC_FORM_RESULT_CANCELLED;
}

static void shim_progress(void *data, int level, const char *fmt, ...)
{
	struct ocshim_ctx *ctx = data;
	char buffer[2048];
	va_list args;

	if (!ctx->cb.log)
		return;
	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	ctx->cb.log(ctx->priv, level, buffer);
}

static int shim_webview(struct openconnect_info *vpninfo, const char *uri, void *data)
{
	struct ocshim_ctx *ctx = data;
	(void)vpninfo;
	return ctx->cb.webview ? ctx->cb.webview(ctx->priv, uri) : -EINVAL;
}

static int shim_getaddrinfo(void *data, const char *node, const char *service,
			    const struct addrinfo *hints, struct addrinfo **res)
{
	struct ocshim_ctx *ctx = data;
	char address[64];
	struct addrinfo numeric;

	if (!ctx->cb.resolve || !node)
		return getaddrinfo(node, service, hints, res);

	memset(address, 0, sizeof(address));
	if (ctx->cb.resolve(ctx->priv, node, address, sizeof(address) - 1) != 0 || !address[0])
		return EAI_NONAME;

	numeric = *hints;
	numeric.ai_flags |= AI_NUMERICHOST;
	return getaddrinfo(address, service, &numeric, res);
}

static void shim_setup_tun(void *data)
{
	struct ocshim_ctx *ctx = data;
	if (ctx->cb.setup_tun)
		ctx->cb.setup_tun(ctx->priv);
}

static void shim_reconnected(void *data)
{
	struct ocshim_ctx *ctx = data;
	if (ctx->cb.reconnected)
		ctx->cb.reconnected(ctx->priv);
}

static void shim_stats(void *data, const struct oc_stats *stats)
{
	struct ocshim_ctx *ctx = data;
	if (ctx->cb.stats)
		ctx->cb.stats(ctx->priv, stats);
}

__declspec(dllexport) int ocshim_version(void)
{
	return 1;
}

__declspec(dllexport) struct ocshim_ctx *ocshim_new(const char *useragent,
						   const struct ocshim_callbacks *callbacks,
						   void *priv)
{
	struct ocshim_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->cb = *callbacks;
	ctx->priv = priv;
	ctx->vpninfo = openconnect_vpninfo_new(useragent, shim_validate, NULL,
					       shim_form, shim_progress, ctx);
	if (!ctx->vpninfo) {
		free(ctx);
		return NULL;
	}

	openconnect_set_webview_callback(ctx->vpninfo, shim_webview);
	openconnect_set_setup_tun_handler(ctx->vpninfo, shim_setup_tun);
	openconnect_set_reconnected_handler(ctx->vpninfo, shim_reconnected);
	openconnect_set_stats_handler(ctx->vpninfo, shim_stats);
	if (callbacks->resolve)
		openconnect_override_getaddrinfo(ctx->vpninfo, shim_getaddrinfo);
	return ctx;
}

__declspec(dllexport) struct openconnect_info *ocshim_vpninfo(struct ocshim_ctx *ctx)
{
	return ctx ? ctx->vpninfo : NULL;
}

/* Одна отправка команды OC_CMD_* в сокет, выданный openconnect_setup_cmd_pipe. */
__declspec(dllexport) int ocshim_send_cmd(SOCKET sock, char cmd)
{
	return send(sock, &cmd, 1, 0) == 1 ? 0 : -1;
}

__declspec(dllexport) void ocshim_free(struct ocshim_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->vpninfo)
		openconnect_vpninfo_free(ctx->vpninfo);
	free(ctx);
}
