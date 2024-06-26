/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/*
 * WPA Supplicant / main() function for Zephyr OS
 * Copyright (c) 2003-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <zephyr/logging/log.h>
#include <sys/fcntl.h>
LOG_MODULE_REGISTER(wpa_supplicant, LOG_LEVEL_DBG);

#include "includes.h"
#include "utils/common.h"
#include "eloop.h"
#include "wpa_supplicant/config.h"
#include "wpa_supplicant_i.h"

#include "fst/fst.h"
#include "includes.h"
#include "p2p_supplicant.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"

#ifdef CONFIG_WPA_SUPP_AP
#include "utils/uuid.h"
#include "crypto/random.h"
#include "crypto/tls.h"
#include "common/version.h"
#include "common/dpp.h"
#include "drivers/driver.h"
#include "eap_server/eap.h"
#include "eap_server/tncs.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"
#include "ap/ap_drv_ops.h"
#include "ap/dpp_hostapd.h"
#include "config_file.h"
#include "eap_register.h"
#include "ctrl_iface.h"
#endif

#include "supp_main.h"
#include "crc32.h"

K_SEM_DEFINE(wpa_supplicant_ready_sem, 0, 1);
K_SEM_DEFINE(hostapd_ready_sem, 0, 1);

struct wpa_global *global;

static int wpa_event_sockpair[2];

static void start_wpa_supplicant(void);

K_THREAD_DEFINE(wpa_s_tid, CONFIG_WPA_SUPP_THREAD_STACK_SIZE, start_wpa_supplicant, NULL, NULL, NULL, 0, 0, 0);

struct hapd_global
{
    void **drv_priv;
    size_t drv_count;
};

static void hostapd_main_task(void);
static void hostapd_task_cleanup(void);

#ifdef CONFIG_MATCH_IFACE
static int wpa_supplicant_init_match(struct wpa_global *global)
{
    /*
     * The assumption is that the first driver is the primary driver and
     * will handle the arrival / departure of interfaces.
     */
    if (wpa_drivers[0]->global_init && !global->drv_priv[0])
    {
        global->drv_priv[0] = wpa_drivers[0]->global_init(global);
        if (!global->drv_priv[0])
        {
            wpa_printf(MSG_ERROR, "Failed to initialize driver '%s'", wpa_drivers[0]->name);
            return -1;
        }
    }

    return 0;
}
#endif /* CONFIG_MATCH_IFACE */

#include "config.h"
static void iface_cb(struct net_if *iface, void *user_data)
{
    struct wpa_interface *ifaces   = user_data;
    struct net_linkaddr *link_addr = NULL;
    int ifindex;
    char own_addr[NET_LINK_ADDR_MAX_LENGTH];
    char *ifname;

    ifindex   = net_if_get_by_iface(iface);
    link_addr = &iface->if_dev->link_addr;
    /* 802.15.4 interface, ignore */
    if (link_addr->len > NET_LINK_ADDR_MAX_LENGTH)
    {
        return;
    }
    os_memcpy(own_addr, link_addr->addr, link_addr->len);
    ifname = os_strdup(iface->if_dev->dev->name);

    wpa_printf(MSG_INFO, "iface_cb: iface %s ifindex %d %02x:%02x:%02x:%02x:%02x:%02x", ifname ? ifname : "Unknown",
               ifindex, own_addr[0], own_addr[1], own_addr[2], own_addr[3], own_addr[4], own_addr[5]);

    /* TODO : make this user configurable*/
    ifaces[0].ifname = "wlan0";

    os_free(ifname);
}

static void wpa_event_sock_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
    int ret;
    ARG_UNUSED(eloop_ctx);
    ARG_UNUSED(sock_ctx);
    struct wpa_supplicant_event_msg msg;

    ret = recv(sock, &msg, sizeof(msg), 0);

    if (ret < 0)
    {
        wpa_printf(MSG_ERROR, "Failed to recv the message: %s", strerror(errno));
        return;
    }

    if (ret != sizeof(msg))
    {
        wpa_printf(MSG_ERROR, "Recieved incomplete message: got: %d, expected:%d", ret, sizeof(msg));
        return;
    }

    if (msg.ignore_msg)
    {
        return;
    }

    wpa_printf(MSG_DEBUG, "Passing message %d to %s", msg.event, msg.hostapd == 1 ? "hostapd" : "wpa_supplicant");

#ifdef CONFIG_HOSTAPD
    if (msg.hostapd)
        hostapd_event(msg.ctx, msg.event, msg.data);
    else
#endif
        wpa_supplicant_event(msg.ctx, msg.event, msg.data);

    if (msg.data)
    {
        os_free(msg.data);
    }
}

static int register_wpa_event_sock(void)
{
    int ret;

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, wpa_event_sockpair);

    if (ret != 0)
    {
        wpa_printf(MSG_ERROR, "Failed to initialize socket: %s", strerror(errno));
        return -1;
    }

    eloop_register_read_sock(wpa_event_sockpair[0], wpa_event_sock_handler, NULL, NULL);

    return 0;
}

int send_wpa_supplicant_event(const struct wpa_supplicant_event_msg *msg)
{
    int ret;
    unsigned int retry = 0;

    if (wpa_event_sockpair[1] < 0)
    {
        return -1;
    }

retry_send:
    ret = send(wpa_event_sockpair[1], msg, sizeof(*msg), 0);
    if (ret < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EBUSY || errno == EWOULDBLOCK)
        {
            k_msleep(2);
            if (retry++ < 3)
            {
                goto retry_send;
            }
            else
            {
                wpa_printf(MSG_WARNING, "Dummy socket send fail (max retries): %s", strerror(errno));
                return -1;
            }
        }
        else
        {
            wpa_printf(MSG_WARNING, "Dummy socket send fail: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

static void start_wpa_supplicant(void)
{
    int i;
    struct wpa_interface *ifaces, *iface;
    int iface_count, exitcode = -1;
    struct wpa_params params;

    os_memset(&params, 0, sizeof(params));
    params.wpa_debug_level = CONFIG_WPA_SUPP_DEBUG_LEVEL;

    wpa_printf(MSG_INFO, "%s: %d Starting wpa_supplicant thread with debug level: %d\n", __func__, __LINE__,
               params.wpa_debug_level);

    iface = ifaces = os_zalloc(sizeof(struct wpa_interface));
    if (ifaces == NULL)
    {
        return;
    }
    iface_count = 1;

    exitcode = 0;
    global   = wpa_supplicant_init(&params);
    if (global == NULL)
    {
        wpa_printf(MSG_ERROR, "Failed to initialize wpa_supplicant");
        exitcode = -1;
        goto out;
    }
    else
    {
        wpa_printf(MSG_INFO,
                   "Successfully initialized "
                   "wpa_supplicant");
    }

#if 0
    if (fst_global_init())
    {
        wpa_printf(MSG_ERROR, "Failed to initialize FST");
        exitcode = -1;
        goto out;
    }

#if defined(CONFIG_FST) && defined(CONFIG_CTRL_IFACE)
    if (!fst_global_add_ctrl(fst_ctrl_cli))
    {
        wpa_printf(MSG_WARNING, "Failed to add CLI FST ctrl");
    }
#endif
#endif

    net_if_foreach(iface_cb, ifaces);

    ifaces[0].ctrl_interface = "test_ctrl";
    params.ctrl_interface    = "test_ctrl";
    wpa_printf(MSG_INFO, "Using interface %s\n", ifaces[0].ifname);

#ifdef CONFIG_HOSTAPD
    hostapd_main_task();
#endif

    for (i = 0; exitcode == 0 && i < iface_count; i++)
    {
        struct wpa_supplicant *wpa_s;

        if ((ifaces[i].confname == NULL && ifaces[i].ctrl_interface == NULL) || ifaces[i].ifname == NULL)
        {
            if (iface_count == 1 && (params.ctrl_interface ||
#ifdef CONFIG_MATCH_IFACE
                                     params.match_iface_count ||
#endif /* CONFIG_MATCH_IFACE */
                                     params.dbus_ctrl_interface))
                break;
            wpa_printf(MSG_INFO, "Failed to initialize interface %d\n", i);
            exitcode = -1;
            break;
        }
        wpa_printf(MSG_INFO, "Initializing interface %d: %s\n", i, ifaces[i].ifname);
        wpa_s = wpa_supplicant_add_iface(global, &ifaces[i], NULL);
        if (wpa_s == NULL)
        {
            exitcode = -1;
            break;
        }
        wpa_s->conf->filter_ssids = 1;
        wpa_s->conf->ap_scan      = 1;
    }

    register_wpa_event_sock();

#ifdef CONFIG_MATCH_IFACE
    if (exitcode == 0)
    {
        exitcode = wpa_supplicant_init_match(global);
    }
#endif /* CONFIG_MATCH_IFACE */

    if (exitcode == 0)
    {
        k_sem_give(&wpa_supplicant_ready_sem);
        exitcode = wpa_supplicant_run(global);
    }

#ifdef CONFIG_HOSTAPD
    hostapd_task_cleanup();
#endif

    eloop_unregister_read_sock(wpa_event_sockpair[0]);

    wpa_supplicant_deinit(global);

#if 0
    fst_global_deinit();
#endif

    close(wpa_event_sockpair[0]);
    close(wpa_event_sockpair[1]);

out:
    os_free(ifaces);
#ifdef CONFIG_MATCH_IFACE
    os_free(params.match_ifaces);
#endif /* CONFIG_MATCH_IFACE */
    // os_free(params.pid_file);

    wpa_printf(MSG_INFO, "wpa_supplicant_main: exitcode %d", exitcode);

    k_sem_give(&wpa_supplicant_ready_sem);

    return;
}

int stop_wpa_supplicant(void)
{
    k_sem_take(&wpa_supplicant_ready_sem, K_FOREVER);

    eloop_terminate();

    k_sem_take(&wpa_supplicant_ready_sem, K_FOREVER);

    return 0;
}

#ifndef CONFIG_NO_HOSTAPD_LOGGER
static void hostapd_logger_cb(void *ctx, const u8 *addr, unsigned int module, int level, const char *txt, size_t len)
{
    struct hostapd_data *hapd = ctx;
    char *format, *module_str;
    int maxlen;
    int conf_syslog_level, conf_stdout_level;
    unsigned int conf_syslog, conf_stdout;

    maxlen = len + 100;
    format = os_malloc(maxlen);
    if (!format)
        return;

    if (hapd && hapd->conf)
    {
        conf_syslog_level = hapd->conf->logger_syslog_level;
        conf_stdout_level = hapd->conf->logger_stdout_level;
        conf_syslog       = hapd->conf->logger_syslog;
        conf_stdout       = hapd->conf->logger_stdout;
    }
    else
    {
        conf_syslog_level = conf_stdout_level = 0;
        conf_syslog = conf_stdout = (unsigned int)-1;
    }

    switch (module)
    {
        case HOSTAPD_MODULE_IEEE80211:
            module_str = "IEEE 802.11";
            break;
        case HOSTAPD_MODULE_IEEE8021X:
            module_str = "IEEE 802.1X";
            break;
        case HOSTAPD_MODULE_RADIUS:
            module_str = "RADIUS";
            break;
        case HOSTAPD_MODULE_WPA:
            module_str = "WPA";
            break;
        case HOSTAPD_MODULE_DRIVER:
            module_str = "DRIVER";
            break;
        case HOSTAPD_MODULE_MLME:
            module_str = "MLME";
            break;
        default:
            module_str = NULL;
            break;
    }

    if (hapd && hapd->conf && addr)
        os_snprintf(format, maxlen, "%s: STA " MACSTR "%s%s: %s", hapd->conf->iface, MAC2STR(addr),
                    module_str ? " " : "", module_str ? module_str : "", txt);
    else if (hapd && hapd->conf)
        os_snprintf(format, maxlen, "%s:%s%s %s", hapd->conf->iface, module_str ? " " : "",
                    module_str ? module_str : "", txt);
    else if (addr)
        os_snprintf(format, maxlen, "STA " MACSTR "%s%s: %s", MAC2STR(addr), module_str ? " " : "",
                    module_str ? module_str : "", txt);
    else
        os_snprintf(format, maxlen, "%s%s%s", module_str ? module_str : "", module_str ? ": " : "", txt);

#ifdef CONFIG_DEBUG_SYSLOG
    if (wpa_debug_syslog)
        conf_stdout = 0;
#endif /* CONFIG_DEBUG_SYSLOG */
    if ((conf_stdout & module) && level >= conf_stdout_level)
    {
        // wpa_debug_print_timestamp();
        wpa_printf(MSG_INFO, "%s", format);
    }

    if ((conf_syslog & module) && level >= conf_syslog_level)
    {
        /* do nothing */
    }
#if 0
  //ndef CONFIG_NATIVE_WINDOWS
    if ((conf_syslog & module) && level >= conf_syslog_level)
    {
        int priority;
        switch (level)
        {
            case HOSTAPD_LEVEL_DEBUG_VERBOSE:
            case HOSTAPD_LEVEL_DEBUG:
                priority = LOG_DEBUG;
                break;
            case HOSTAPD_LEVEL_INFO:
                priority = LOG_INFO;
                break;
            case HOSTAPD_LEVEL_NOTICE:
                priority = LOG_NOTICE;
                break;
            case HOSTAPD_LEVEL_WARNING:
                priority = LOG_WARNING;
                break;
            default:
                priority = LOG_INFO;
                break;
        }
        syslog(priority, "%s", format);
    }
#endif /* CONFIG_NATIVE_WINDOWS */

    os_free(format);
}
#endif /* CONFIG_NO_HOSTAPD_LOGGER */

/**
 * hostapd_driver_init - Preparate driver interface
 */
static int hostapd_driver_init(struct hostapd_iface *iface)
{
    struct wpa_init_params params;
    size_t i;
    struct hostapd_data *hapd       = iface->bss[0];
    struct hostapd_bss_config *conf = hapd->conf;
    u8 *b                           = conf->bssid;
    struct wpa_driver_capa capa;

    if (hapd->driver == NULL || hapd->driver->hapd_init == NULL)
    {
        wpa_printf(MSG_ERROR, "No hostapd driver wrapper available");
        return -1;
    }

    /* Initialize the driver interface */
    if (!(b[0] | b[1] | b[2] | b[3] | b[4] | b[5]))
        b = NULL;

    os_memset(&params, 0, sizeof(params));
    for (i = 0; wpa_drivers[i]; i++)
    {
        if (wpa_drivers[i] != hapd->driver)
            continue;

        if (hglobal.drv_priv[i] == NULL && wpa_drivers[i]->global_init)
        {
            hglobal.drv_priv[i] = wpa_drivers[i]->global_init(iface->interfaces);
            if (hglobal.drv_priv[i] == NULL)
            {
                wpa_printf(MSG_ERROR,
                           "Failed to initialize "
                           "driver '%s'",
                           wpa_drivers[i]->name);
                return -1;
            }
        }

        params.global_priv = hglobal.drv_priv[i];
        break;
    }
    params.bssid              = b;
    params.ifname             = hapd->conf->iface;
    params.driver_params      = hapd->iconf->driver_params;
    params.use_pae_group_addr = hapd->conf->use_pae_group_addr;

    params.num_bridge = hapd->iface->num_bss;
    params.bridge     = os_calloc(hapd->iface->num_bss, sizeof(char *));
    if (params.bridge == NULL)
        return -1;
    for (i = 0; i < hapd->iface->num_bss; i++)
    {
        struct hostapd_data *bss = hapd->iface->bss[i];
        if (bss->conf->bridge[0])
            params.bridge[i] = bss->conf->bridge;
    }

    params.own_addr = hapd->own_addr;

    hapd->drv_priv = hapd->driver->hapd_init(hapd, &params);
    os_free(params.bridge);
    if (hapd->drv_priv == NULL)
    {
        wpa_printf(MSG_ERROR, "%s driver initialization failed.", hapd->driver->name);
        hapd->driver = NULL;
        return -1;
    }

    if (hapd->driver->get_capa && hapd->driver->get_capa(hapd->drv_priv, &capa) == 0)
    {
        struct wowlan_triggers *triggs;

        iface->drv_flags           = capa.flags;
        iface->drv_flags2          = capa.flags2;
        iface->probe_resp_offloads = capa.probe_resp_offloads;
        /*
         * Use default extended capa values from per-radio information
         */
        iface->extended_capa         = capa.extended_capa;
        iface->extended_capa_mask    = capa.extended_capa_mask;
        iface->extended_capa_len     = capa.extended_capa_len;
        iface->drv_max_acl_mac_addrs = capa.max_acl_mac_addrs;

        /*
         * Override extended capa with per-interface type (AP), if
         * available from the driver.
         */
        hostapd_get_ext_capa(iface);

        triggs = wpa_get_wowlan_triggers(conf->wowlan_triggers, &capa);
        if (triggs && hapd->driver->set_wowlan)
        {
            if (hapd->driver->set_wowlan(hapd->drv_priv, triggs))
                wpa_printf(MSG_ERROR, "set_wowlan failed");
        }
        os_free(triggs);
    }

    return 0;
}

/**
 * hostapd_interface_init - Read configuration file and init BSS data
 *
 * This function is used to parse configuration file for a full interface (one
 * or more BSSes sharing the same radio) and allocate memory for the BSS
 * interfaces. No actual driver operations are started.
 */
static struct hostapd_iface *hostapd_interface_init(struct hapd_interfaces *interfaces,
                                                    const char *if_name,
                                                    const char *config_fname,
                                                    int debug)
{
    struct hostapd_iface *iface;
    int k;

    wpa_printf(MSG_DEBUG, "Configuration file: %s", config_fname);
    iface = hostapd_init(interfaces, config_fname);
    if (!iface)
        return NULL;

    if (if_name)
    {
        os_strlcpy(iface->conf->bss[0]->iface, if_name, sizeof(iface->conf->bss[0]->iface));
    }

    iface->interfaces = interfaces;

    for (k = 0; k < debug; k++)
    {
        if (iface->bss[0]->conf->logger_stdout_level > 0)
            iface->bss[0]->conf->logger_stdout_level--;
    }

    if (iface->conf->bss[0]->iface[0] == '\0' && !hostapd_drv_none(iface->bss[0]))
    {
        wpa_printf(MSG_ERROR, "Interface name not specified in %s, nor by '-i' parameter", config_fname);
        hostapd_interface_deinit_free(iface);
        return NULL;
    }

    return iface;
}

#if 0
/**
 * handle_term - SIGINT and SIGTERM handler to terminate hostapd process
 */
static void handle_term(int sig, void *signal_ctx)
{
    wpa_printf(MSG_DEBUG, "Signal %d received - terminating", sig);
    eloop_terminate();
}

#ifndef CONFIG_NATIVE_WINDOWS

static int handle_reload_iface(struct hostapd_iface *iface, void *ctx)
{
    if (hostapd_reload_config(iface) < 0)
    {
        wpa_printf(MSG_WARNING,
                   "Failed to read new configuration "
                   "file - continuing with old.");
    }
    return 0;
}

/**
 * handle_reload - SIGHUP handler to reload configuration
 */
static void handle_reload(int sig, void *signal_ctx)
{
    struct hapd_interfaces *interfaces = signal_ctx;
    wpa_printf(MSG_DEBUG, "Signal %d received - reloading configuration", sig);
    hostapd_for_each_interface(interfaces, handle_reload_iface, NULL);
}

static void handle_dump_state(int sig, void *signal_ctx)
{
    /* Not used anymore - ignore signal */
}
#endif /* CONFIG_NATIVE_WINDOWS */
#endif

static int hostapd_global_init(struct hapd_interfaces *interfaces, const char *entropy_file)
{
    int i;

    os_memset(&hglobal, 0, sizeof(hglobal));

    hostapd_logger_register_cb(hostapd_logger_cb);

    if (eap_server_register_methods())
    {
        wpa_printf(MSG_ERROR, "Failed to register EAP methods");
        return -1;
    }

    if (eloop_init())
    {
        wpa_printf(MSG_ERROR, "Failed to initialize event loop");
        return -1;
    }

    interfaces->eloop_initialized = 1;

    random_init(entropy_file);

#if 0
#ifndef CONFIG_NATIVE_WINDOWS
    eloop_register_signal(SIGHUP, handle_reload, interfaces);
    eloop_register_signal(SIGUSR1, handle_dump_state, interfaces);
#endif /* CONFIG_NATIVE_WINDOWS */
    eloop_register_signal_terminate(handle_term, interfaces);

#ifndef CONFIG_NATIVE_WINDOWS
    openlog("hostapd", 0, LOG_DAEMON);
#endif /* CONFIG_NATIVE_WINDOWS */
#endif

    for (i = 0; wpa_drivers[i]; i++)
        hglobal.drv_count++;
    if (hglobal.drv_count == 0)
    {
        wpa_printf(MSG_ERROR, "No drivers enabled");
        return -1;
    }
    hglobal.drv_priv = os_calloc(hglobal.drv_count, sizeof(void *));
    if (hglobal.drv_priv == NULL)
        return -1;

    return 0;
}

static void hostapd_global_deinit(const char *pid_file, int eloop_initialized)
{
    int i;

    for (i = 0; wpa_drivers[i] && hglobal.drv_priv; i++)
    {
        if (!hglobal.drv_priv[i])
            continue;
        wpa_drivers[i]->global_deinit(hglobal.drv_priv[i]);
    }
    os_free(hglobal.drv_priv);
    hglobal.drv_priv = NULL;

#ifdef EAP_SERVER_TNC
    tncs_global_deinit();
#endif /* EAP_SERVER_TNC */

    random_deinit();

    // if (eloop_initialized)
    //    eloop_destroy();

#if 0
#ifndef CONFIG_NATIVE_WINDOWS
    closelog();
#endif /* CONFIG_NATIVE_WINDOWS */
#endif
    // eap_server_unregister_methods();

    // os_daemonize_terminate(pid_file);
}

static int hostapd_global_run(struct hapd_interfaces *ifaces, int daemonize, const char *pid_file)
{
#ifdef EAP_SERVER_TNC
    int tnc = 0;
    size_t i, k;

    for (i = 0; !tnc && i < ifaces->count; i++)
    {
        for (k = 0; k < ifaces->iface[i]->num_bss; k++)
        {
            if (ifaces->iface[i]->bss[0]->conf->tnc)
            {
                tnc++;
                break;
            }
        }
    }

    if (tnc && tncs_global_init() < 0)
    {
        wpa_printf(MSG_ERROR, "Failed to initialize TNCS");
        return -1;
    }
#endif /* EAP_SERVER_TNC */

    if (daemonize)
    {
        if (os_daemonize(pid_file))
        {
            wpa_printf(MSG_ERROR, "daemon: %s", strerror(errno));
            return -1;
        }
        if (eloop_sock_requeue())
        {
            wpa_printf(MSG_ERROR, "eloop_sock_requeue: %s", strerror(errno));
            return -1;
        }
    }

    eloop_run();

    return 0;
}

static const char *hostapd_msg_ifname_cb(void *ctx)
{
    struct wpa_supplicant *wpa_s = ctx;
    if (wpa_s == NULL)
        return NULL;
    return wpa_s->ifname;
}

#ifndef HOSTAPD_CLEANUP_INTERVAL
#define HOSTAPD_CLEANUP_INTERVAL 10
#endif /* HOSTAPD_CLEANUP_INTERVAL */

static int hostapd_periodic_call(struct hostapd_iface *iface, void *ctx)
{
    hostapd_periodic_iface(iface);
    return 0;
}

/* Periodic cleanup tasks */
static void hostapd_periodic(void *eloop_ctx, void *timeout_ctx)
{
    struct hapd_interfaces *interfaces = eloop_ctx;

    eloop_register_timeout(HOSTAPD_CLEANUP_INTERVAL, 0, hostapd_periodic, interfaces, NULL);
    hostapd_for_each_interface(interfaces, hostapd_periodic_call, NULL);
}

static struct hapd_interfaces interfaces;

struct hapd_interfaces *hostapd_get_ifaces(char *ifname)
{
    return &interfaces;
}

struct hostapd_iface *hostapd_get_interface(const char *ifname)
{
    (void)ifname;
    return interfaces.iface[0];
}

struct hostapd_data *hostapd_get_hapd()
{
    struct hostapd_data *hapd = NULL;
    if (interfaces.iface && interfaces.iface[0] && interfaces.iface[0]->bss && interfaces.iface[0]->bss[0])
    {
        hapd = interfaces.iface[0]->bss[0];
    }
    return hapd;
}

/**
 * hostapd_config_read - Read and parse a configuration file
 * @fname: Configuration file name (including path, if needed)
 * Returns: Allocated configuration data structure
 */
struct hostapd_config *hostapd_config_read2(const char *fname)
{
    // struct netif *netif;
    struct hostapd_config *conf;
    // FILE *f;
    // char buf[4096], *pos = NULL, *g_ssid = "NXP_HAPD", *passphrase = "1234567890";
    // int line   = 0;
    int errors = 0;
    size_t i;
#if 0
    f = fopen(fname, "r");
    if (f == NULL)
    {
        wpa_printf(MSG_ERROR,
                   "Could not open configuration file '%s' "
                   "for reading.",
                   fname);
        return NULL;
    }
#endif

    // netif = net_get_uap_interface();

    char if_name[NETIF_NAMESIZE] = {0};

    // netif_index_to_name(netif->num + 1, if_name);

    conf = hostapd_config_defaults();
    if (conf == NULL)
    {
        // fclose(f);
        return NULL;
    }
    /* set default driver based on configuration */
    conf->driver = wpa_drivers[0];
    if (conf->driver == NULL)
    {
        wpa_printf(MSG_ERROR, "No driver wrappers registered!");
        hostapd_config_free(conf);
        // fclose(f);
        return NULL;
    }
    conf->last_bss = conf->bss[0];
    struct hostapd_bss_config *bss;
    bss                 = conf->last_bss;
    bss->start_disabled = 1;
    os_strlcpy(conf->bss[0]->iface, if_name, sizeof(conf->bss[0]->iface));
    bss->logger_stdout_level = 0;
    bss->logger_stdout       = 0xffff;
    bss->nas_identifier      = os_strdup("ap.example.com");
    os_memcpy(conf->country, "WW ", 3);
    conf->hw_mode        = HOSTAPD_MODE_IEEE80211G;
    bss->wps_state       = WPS_STATE_CONFIGURED;
    bss->eap_server      = 1;
    bss->ap_setup_locked = 1;
    conf->channel        = 1;
    conf->acs            = conf->channel == 0;
#ifdef CONFIG_ACS
    conf->acs_num_scans = 1;
#endif /* CONFIG_ACS */
    conf->ieee80211n = 1;
    conf->ht_capab |= HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    conf->secondary_channel = 1;
    conf->ht_capab |= HT_CAP_INFO_SHORT_GI20MHZ;
    conf->ht_capab |= HT_CAP_INFO_SHORT_GI40MHZ;
    bss->auth_algs = 1;
#if 0
    bss->wpa       = WPA_PROTO_RSN;
    bss->wpa_key_mgmt |= WPA_KEY_MGMT_FT_PSK;
    struct hostapd_ssid *ssid = &bss->ssid;
    ssid->ssid_len            = os_strlen(g_ssid);
    if (ssid->ssid_len > SSID_MAX_LEN || ssid->ssid_len < 1)
    {
        wpa_printf(MSG_ERROR, "Line %d: invalid SSID '%s'", line, ssid->ssid);
        hostapd_config_free(conf);
        return NULL;
    }
    os_memcpy(ssid->ssid, g_ssid, ssid->ssid_len);
    ssid->ssid_set           = 1;
    ssid->short_ssid         = crc32(ssid->ssid, ssid->ssid_len);
    bss->ssid.wpa_passphrase = os_strdup(passphrase);
    if (bss->ssid.wpa_passphrase)
    {
        hostapd_config_clear_wpa_psk(&bss->ssid.wpa_psk);
        bss->ssid.wpa_passphrase_set = 1;
    }
    bss->rsn_pairwise = WPA_CIPHER_CCMP;

    while (fgets(buf, sizeof(buf), f))
    {
        struct hostapd_bss_config *bss;
        bss = conf->last_bss;
        line++;
        if (buf[0] == '#')
            continue;
        pos = buf;
        while (*pos != '\0')
        {
            if (*pos == '\n')
            {
                *pos = '\0';
                break;
            }
            pos++;
        }
        if (buf[0] == '\0')
            continue;
        pos = os_strchr(buf, '=');
        if (pos == NULL)
        {
            wpa_printf(MSG_ERROR, "Line %d: invalid line '%s'", line, buf);
            errors++;
            continue;
        }
        *pos = '\0';
        pos++;
        errors += hostapd_config_fill(conf, bss, buf, pos, line);
    }
    fclose(f);
#endif
    for (i = 0; i < conf->num_bss; i++)
        hostapd_set_security_params(conf->bss[i], 1);
    if (hostapd_config_check(conf, 1))
        errors++;
#ifndef WPA_IGNORE_CONFIG_ERRORS
    if (errors)
    {
        wpa_printf(MSG_ERROR,
                   "%d errors found in configuration file "
                   "'%s'",
                   errors, fname);
        hostapd_config_free(conf);
        conf = NULL;
    }
#endif /* WPA_IGNORE_CONFIG_ERRORS */
    return conf;
}

static int hostapd_enable_iface_cb(struct hostapd_iface *hapd_iface)
{
    struct hostapd_data *bss;

    wpa_printf(MSG_DEBUG, "Enable interface %s", hapd_iface->conf->bss[0]->iface);

    bss = hapd_iface->bss[0];

    bss->conf->start_disabled = 0;

    if (hostapd_setup_interface(hapd_iface))
    {
        wpa_printf(MSG_ERROR, "Failed to initialize hostapd interface");
        return -1;
    }

    return 0;
}

static int hostapd_disable_iface_cb(struct hostapd_iface *hapd_iface)
{
    size_t j;
    struct hostapd_data *hapd = NULL;

    wpa_msg(hapd_iface->bss[0]->msg_ctx, MSG_INFO, AP_EVENT_DISABLED);

    hapd_iface->driver_ap_teardown = !!(hapd_iface->drv_flags & WPA_DRIVER_FLAGS_AP_TEARDOWN_SUPPORT);

#ifdef NEED_AP_MLME
    for (j = 0; j < hapd_iface->num_bss; j++)
        hostapd_cleanup_cs_params(hapd_iface->bss[j]);
#endif /* NEED_AP_MLME */

    /* Same as hostapd_interface_deinit() without deinitializing control
     * interface */
    for (j = 0; j < hapd_iface->num_bss; j++)
    {
        hapd = hapd_iface->bss[j];

        hostapd_bss_deinit_no_free(hapd);
        hostapd_free_hapd_data(hapd);
    }

    hostapd_drv_stop_ap(hapd);

    hostapd_cleanup_iface_partial(hapd_iface);

    wpa_printf(MSG_DEBUG, "Interface %s disabled", hapd_iface->bss[0]->conf->iface);
    hostapd_set_state(hapd_iface, HAPD_IFACE_DISABLED);

    return 0;
}

static void hostapd_main_task()
{
    // osa_status_t status;
    // const char *iface_name = (const char *)arg;
    // struct netif *netif;
    // int ret = 1;
    // struct netif *netif;
    size_t i;
    int /*c,*/ debug = 0, daemonize = 0;
    char *pid_file = NULL;
    // const char *log_file     = NULL;
    const char *entropy_file = NULL;
    // char **bss_config        = NULL; //, **tmp_bss;
    size_t num_bss_configs = 0;
#ifdef CONFIG_DEBUG_LINUX_TRACING
    int enable_trace_dbg = 0;
#endif /* CONFIG_DEBUG_LINUX_TRACING */
    int start_ifaces_in_sync = 0;
    // char **if_names          = NULL;
    // size_t if_names_size     = 0;
#ifdef CONFIG_DPP
    struct dpp_global_config dpp_conf;
#endif /* CONFIG_DPP */

    //   if (os_program_init())
    //     return -1;

    os_memset(&interfaces, 0, sizeof(interfaces));
    interfaces.reload_config      = hostapd_reload_config;
    interfaces.config_read_cb     = hostapd_config_read2;
    interfaces.for_each_interface = hostapd_for_each_interface;
    interfaces.ctrl_iface_init    = hostapd_ctrl_iface_init;
    interfaces.ctrl_iface_deinit  = hostapd_ctrl_iface_deinit;
    interfaces.driver_init        = hostapd_driver_init;
    interfaces.global_iface_path  = NULL;
    interfaces.global_iface_name  = NULL;
    interfaces.global_ctrl_sock   = -1;
    dl_list_init(&interfaces.global_ctrl_dst);
#ifdef CONFIG_ETH_P_OUI
    dl_list_init(&interfaces.eth_p_oui);
#endif /* CONFIG_ETH_P_OUI */
#ifdef CONFIG_DPP
    os_memset(&dpp_conf, 0, sizeof(dpp_conf));
    dpp_conf.cb_ctx = &interfaces;
#ifdef CONFIG_DPP2
    dpp_conf.remove_bi = hostapd_dpp_remove_bi;
#endif /* CONFIG_DPP2 */
    interfaces.dpp = dpp_global_init(&dpp_conf);
    if (!interfaces.dpp)
        return -1;
#endif /* CONFIG_DPP */

#if 0
    for (;;)
    {
        c = getopt(argc, argv, "b:Bde:f:hi:KP:sSTtu:vg:G:");
        if (c < 0)
            break;
        switch (c)
        {
            case 'h':
                usage();
                break;
            case 'd':
                debug++;
                if (wpa_debug_level > 0)
                    wpa_debug_level--;
                break;
            case 'B':
                daemonize++;
                break;
            case 'e':
                entropy_file = optarg;
                break;
            case 'f':
                log_file = optarg;
                break;
            case 'K':
                wpa_debug_show_keys++;
                break;
            case 'P':
                os_free(pid_file);
                pid_file = os_rel2abs_path(optarg);
                break;
            case 't':
                wpa_debug_timestamp++;
                break;
#ifdef CONFIG_DEBUG_LINUX_TRACING
            case 'T':
                enable_trace_dbg = 1;
                break;
#endif /* CONFIG_DEBUG_LINUX_TRACING */
            case 'v':
                show_version();
                exit(1);
            case 'g':
                if (hostapd_get_global_ctrl_iface(&interfaces, optarg))
                    return -1;
                break;
            case 'G':
                if (hostapd_get_ctrl_iface_group(&interfaces, optarg))
                    return -1;
                break;
            case 'b':
                tmp_bss = os_realloc_array(bss_config, num_bss_configs + 1, sizeof(char *));
                if (tmp_bss == NULL)
                    goto out;
                bss_config                    = tmp_bss;
                bss_config[num_bss_configs++] = optarg;
                break;
#ifdef CONFIG_DEBUG_SYSLOG
            case 's':
                wpa_debug_syslog = 1;
                break;
#endif /* CONFIG_DEBUG_SYSLOG */
            case 'S':
                start_ifaces_in_sync = 1;
                break;
#ifdef CONFIG_WPS
            case 'u':
                return gen_uuid(optarg);
#endif /* CONFIG_WPS */
            case 'i':
                if (hostapd_get_interface_names(&if_names, &if_names_size, optarg))
                    goto out;
                break;
            default:
                usage();
                break;
        }
    }

    if (optind == argc && interfaces.global_iface_path == NULL && num_bss_configs == 0)
        usage();
#endif
    wpa_msg_register_ifname_cb(hostapd_msg_ifname_cb);

#if 0
    if (log_file)
        wpa_debug_open_file(log_file);
    if (!log_file && !wpa_debug_syslog)
        wpa_debug_setup_stdout();
#ifdef CONFIG_DEBUG_SYSLOG
    if (wpa_debug_syslog)
        wpa_debug_open_syslog();
#endif /* CONFIG_DEBUG_SYSLOG */
#ifdef CONFIG_DEBUG_LINUX_TRACING
    if (enable_trace_dbg)
    {
        int tret = wpa_debug_open_linux_tracing();
        if (tret)
        {
            wpa_printf(MSG_ERROR, "Failed to enable trace logging");
            return -1;
        }
    }
#endif /* CONFIG_DEBUG_LINUX_TRACING */
#endif

    interfaces.count = 1; // argc - optind;
    if (interfaces.count || num_bss_configs)
    {
        interfaces.iface = os_calloc(interfaces.count + num_bss_configs, sizeof(struct hostapd_iface *));
        if (interfaces.iface == NULL)
        {
            wpa_printf(MSG_ERROR, "malloc failed");
            return;
        }
    }

    if (hostapd_global_init(&interfaces, entropy_file))
    {
        wpa_printf(MSG_ERROR, "Failed to initialize global context");
        return;
    }

    eloop_register_timeout(HOSTAPD_CLEANUP_INTERVAL, 0, hostapd_periodic, &interfaces, NULL);

#if 0

    if (fst_global_init())
    {
        wpa_printf(MSG_ERROR, "Failed to initialize global FST context");
        goto out;
    }

#if defined(CONFIG_FST) && defined(CONFIG_CTRL_IFACE)
    if (!fst_global_add_ctrl(fst_ctrl_cli))
        wpa_printf(MSG_WARNING, "Failed to add CLI FST ctrl");
#endif /* CONFIG_FST && CONFIG_CTRL_IFACE */
#endif

    /* Allocate and parse configuration for full interface files */

    // netif = net_get_uap_interface();

    char if_name[NETIF_NAMESIZE] = {0};

    // netif_index_to_name(netif->num + 1, if_name);

    for (i = 0; i < interfaces.count; i++)
    {
        interfaces.iface[i] = hostapd_interface_init(&interfaces, if_name, "hostapd.conf", debug);
        if (!interfaces.iface[i])
        {
            wpa_printf(MSG_ERROR, "Failed to initialize interface");
            goto out;
        }
        if (start_ifaces_in_sync)
            interfaces.iface[i]->need_to_start_in_sync = 1;
    }

#if 0
    /* Allocate and parse configuration for per-BSS files */
    for (i = 0; i < num_bss_configs; i++)
    {
        struct hostapd_iface *iface;
        char *fname;

        wpa_printf(MSG_INFO, "BSS config: %s", bss_config[i]);
        fname = os_strchr(bss_config[i], ':');
        if (fname == NULL)
        {
            wpa_printf(MSG_ERROR, "Invalid BSS config identifier '%s'", bss_config[i]);
            goto out;
        }
        *fname++ = '\0';
        iface    = hostapd_interface_init_bss(&interfaces, bss_config[i], fname, debug);
        if (iface == NULL)
            goto out;
        for (j = 0; j < interfaces.count; j++)
        {
            if (interfaces.iface[j] == iface)
                break;
        }
        if (j == interfaces.count)
        {
            struct hostapd_iface **tmp;
            tmp = os_realloc_array(interfaces.iface, interfaces.count + 1, sizeof(struct hostapd_iface *));
            if (tmp == NULL)
            {
                hostapd_interface_deinit_free(iface);
                goto out;
            }
            interfaces.iface                     = tmp;
            interfaces.iface[interfaces.count++] = iface;
        }
    }
#endif

    /*
     * Enable configured interfaces. Depending on channel configuration,
     * this may complete full initialization before returning or use a
     * callback mechanism to complete setup in case of operations like HT
     * co-ex scans, ACS, or DFS are needed to determine channel parameters.
     * In such case, the interface will be enabled from eloop context within
     * hostapd_global_run().
     */
    interfaces.terminate_on_error = 0;
    for (i = 0; i < interfaces.count; i++)
    {
        if (hostapd_driver_init(interfaces.iface[i])) // || hostapd_setup_interface(interfaces.iface[i]))
            goto out;

        interfaces.iface[i]->enable_iface_cb  = hostapd_enable_iface_cb;
        interfaces.iface[i]->disable_iface_cb = hostapd_disable_iface_cb;
    }

    hostapd_global_ctrl_iface_init(&interfaces);

    k_sem_give(&hostapd_ready_sem);

out:
    return;
}

static void hostapd_task_cleanup(void)
{
    int i;
    hostapd_global_ctrl_iface_deinit(&interfaces);
    /* Deinitialize all interfaces */
    for (i = 0; i < interfaces.count; i++)
    {
        if (!interfaces.iface[i])
            continue;
        interfaces.iface[i]->driver_ap_teardown =
            !!(interfaces.iface[i]->drv_flags & WPA_DRIVER_FLAGS_AP_TEARDOWN_SUPPORT);
        hostapd_interface_deinit_free(interfaces.iface[i]);
        interfaces.iface[i] = NULL;
    }
    os_free(interfaces.iface);
    interfaces.iface = NULL;
    interfaces.count = 0;

#ifdef CONFIG_DPP
    dpp_global_deinit(interfaces.dpp);
#endif /* CONFIG_DPP */

    if (interfaces.eloop_initialized)
        eloop_cancel_timeout(hostapd_periodic, &interfaces, NULL);
    hostapd_global_deinit(NULL, interfaces.eloop_initialized);

#if 0
    wpa_debug_close_syslog();
    if (log_file)
        wpa_debug_close_file();
    wpa_debug_close_linux_tracing();
#endif

    // os_free(bss_config);

    // for (i = 0; i < if_names_size; i++)
    //    os_free(if_names[i]);
    // os_free(if_names);

    // fst_global_deinit();

    // os_program_deinit();

    // sys_thread_delete(hostapd_thread);
    return;
}
