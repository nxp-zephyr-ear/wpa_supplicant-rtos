/*
 * Driver interaction with Zephyr WLAN device drivers.
 * Copyright (c) 2022, Nordic Semiconductor
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DRIVER_ZEPHYR_H
#define DRIVER_ZEPHYR_H

#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/ethernet.h>

#include "driver.h"
#include "wpa_supplicant_i.h"
#include "bss.h"

struct zep_drv_ctx
{
    void *supp_ctx;
};

struct zep_drv_if_ctx
{
    struct zep_drv_ctx *drv_ctx;
    void *supp_if_ctx;
    const struct device *dev_ctx;
    void *dev_priv;
    struct zep_wpa_supp_dev_ops *dev_ops;

    u8 *extended_capa, *extended_capa_mask;
    unsigned int extended_capa_len;

    u8 addr[ETH_ALEN];

    struct hostapd_data *hapd;
    int is_ap;
    int beacon_set;
    union wpa_event_data *data;
    bool survey_res_get_in_prog;

    struct wpa_scan_results *scan_res2;
    bool scan_res2_get_in_prog;

    unsigned int assoc_freq;
    unsigned char ssid[SSID_MAX_LEN];
    size_t ssid_len;
    unsigned char bssid[6];
    bool associated;
};

struct zep_wpa_supp_dev_callbk_fns
{
    void (*scan_start)(struct zep_drv_if_ctx *if_ctx);

    void (*scan_abort)(struct zep_drv_if_ctx *if_ctx);

    void (*scan_done)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*survey_res)(struct zep_drv_if_ctx *if_ctx, struct freq_survey *survey, bool more_res);

    void (*auth_resp)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*assoc_resp)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event, unsigned int status);

    void (*deauth)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*disassoc)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*acs_channel_sel)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*mgmt_tx_status)(struct zep_drv_if_ctx *if_ctx, const u8 *frame, size_t len, bool ack);

    void (*unprot_deauth)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*unprot_disassoc)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*remain_on_channel)(struct zep_drv_if_ctx *if_ctx, int cancel_event, union wpa_event_data *event);

    void (*mgmt_rx)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);
};

struct zep_hostapd_dev_callbk_fns
{
    void (*scan_done)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*survey_res)(struct zep_drv_if_ctx *if_ctx, struct freq_survey *survey, bool more_res);

    void (*acs_channel_sel)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*mgmt_rx)(struct zep_drv_if_ctx *if_ctx, union wpa_event_data *event);

    void (*mgmt_tx_status)(struct zep_drv_if_ctx *if_ctx, const u8 *frame, size_t len, bool ack);
};

struct zep_wpa_supp_dev_ops
{
    void *(*init)(void *supp_drv_if_ctx, const char *iface_name, struct zep_wpa_supp_dev_callbk_fns *callbk_fns);
    void (*deinit)(void *if_priv);
    int (*set_mac_addr)(void *priv, const u8 *addr);
    int (*scan2)(void *if_priv, struct wpa_driver_scan_params *params);
    int (*sched_scan)(void *priv, struct wpa_driver_scan_params *params);
    int (*stop_sched_scan)(void *priv);
    int (*scan_abort)(void *if_priv);
    int (*get_scan_results2)(void *if_priv, struct wpa_scan_results *scan_res2);
    int (*deauthenticate)(void *if_priv, const char *addr, unsigned short reason_code);
    int (*authenticate)(void *if_priv, struct wpa_driver_auth_params *params, struct wpa_bss *curr_bss);
    int (*associate)(void *if_priv, struct wpa_driver_associate_params *params);
    int (*set_key)(void *if_priv,
                   const unsigned char *ifname,
                   enum wpa_alg alg,
                   const unsigned char *addr,
                   int key_idx,
                   int set_tx,
                   const unsigned char *seq,
                   size_t seq_len,
                   const unsigned char *key,
                   size_t key_len,
                   enum key_flag key_flag);
    int (*set_supp_port)(void *if_priv, int authorized, char *bssid);
    int (*set_country)(void *priv, const char *alpha2);
    int (*get_country)(void *priv, char *alpha2);
    int (*signal_poll)(void *if_priv, struct wpa_signal_info *si, unsigned char *bssid);
    int (*send_mlme)(void *if_priv,
                     const u8 *data,
                     size_t data_len,
                     int noack,
                     unsigned int freq,
                     int no_cck,
                     int offchanok,
                     unsigned int wait_time,
                     int cookie);
    int (*remain_on_channel)(void *priv, unsigned int freq, unsigned int duration);
    int (*cancel_remain_on_channel)(void *priv);
    void *(*hapd_init)(void *hapd_drv_if_ctx,
                       const char *iface_name,
                       struct zep_hostapd_dev_callbk_fns *hostapd_callbk_fns);
    void (*hapd_deinit)(void *priv);
    int (*set_modes)(void *if_priv, struct hostapd_hw_modes *modes);
    int (*get_survey_results)(void *if_priv);
    int (*do_acs)(void *priv, struct drv_acs_params *params);
    int (*set_ap)(void *priv, int beacon_set, struct wpa_driver_ap_params *params);
    int (*sta_add)(void *priv, struct hostapd_sta_add_params *params);
    int (*sta_remove)(void *priv, const u8 *addr);
    int (*hapd_send_eapol)(void *priv, const u8 *data, size_t data_len);
    int (*set_freq)(void *if_priv, struct hostapd_freq_params *freq);
    int (*set_rts)(void *if_priv, int rts_threshold);
    int (*set_frag)(void *if_priv, int frag_threshold);
    int (*sta_deauth)(void *if_priv, const char *addr, unsigned short reason_code);
    int (*stop_ap)(void *if_priv);
    int (*deinit_ap)(void *if_priv);
    int (*set_acl)(void *if_priv, struct hostapd_acl_params *params);
};

#endif /* DRIVER_ZEPHYR_H */
