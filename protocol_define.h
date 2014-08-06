#pragma once
#define P_ERROR 0xffff
#define P_NOT_IP -2
#define P_NOT_TCP -1  //如果是UDP可以返回这个值
#define P_WAIT 0 //还不能确定的情况


#define P_UNKNOW_TCP 1
#define P_DNS_TCP 2
#define P_DNS_UDP 3
#define P_FTP 4
#define P_HTTP 5
#define P_IMAP 6
#define P_POP3 7
#define P_SMTP 8

