#ifndef __NET_MONITOR_H
#define __NET_MONITOR_H

struct event {
    unsigned int len;
    char dev[16]; // 网卡名称，如 "eth0"
};

#endif /* __NET_MONITOR_H */
