/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"


#include "dhcpserver.h"
#include "dnsserver.h"

typedef struct TCP_SERVER_T_ {
    struct tcp_pcb *server_pcb;
    bool complete;
    ip_addr_t gw;
} TCP_SERVER_T;


typedef enum {
    METHOD,
    PATH,
    PROTOCOL,
    HEADER,
    LINE_DELIM,
} RequestPart;

#define MAX_REQUEST_SIZE    4096

//const size_t HEADER_BUF_SIZE = 64;
#define HEADER_BUF_SIZE 64

const char EXPECTED_METHOD[] = "GET ";
const char EXPECTED_PATH[] = "/ ";
const char EXPECTED_PROTOCOL[] = "HTTP/1.1\r\n";
const char EXPECTED_HEADER_UPGRADE[] = "Upgrade: websocket";
const char EXPECTED_HEADER_CONNECTION[] = "Connection: Upgrade";
const char EXPECTED_HEADER_WS_VERSION[] = "Sec-WebSocket-Version: 13";
const char EXPECTED_HEADER_NAME_WS_KEY[] = "Sec-WebSocket-Key: ";
const size_t WS_KEY_BASE64_MAX = 24;
const char WS_KEY_MAGIC[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const size_t SHA1_SIZE = 20;
const size_t SHA1_BASE64_SIZE = 28;

#define WS_KEY_COMBINED_BUFFER  (WS_KEY_BASE64_MAX + sizeof(WS_KEY_MAGIC))



#define MSFT_CON_TST    "connecttest"


#define HTTP_GET "GET"


const char NOT_FOUND_RESPONSE[] =
  "HTTP/1.1 404 Not Found\n"
  "Connection: close\n";

const char BAD_METHOD_RESPONSE[] =
  "HTTP/1.1 405 Method Not Allowed\r\n"
  "Connection: close\n";

const char HTML_RESPONSE_START[] =
  "HTTP/1.1 200 OK\n"
  "Content-Type: text/html\n"
  "charset=utf-8\n"
  "Content-Length: ";


#define HTTP_RESPONSE_HEADERS "HTTP/1.1 %d OK\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nConnection: close\n\n"


const char HTML_RESPONSE_END[] = "Connection: close\n\n";



const char *HEADER_CONTINUE_RESPONSE = "Expect: 100-continue\n";


const char UPGRADE_RESPONSE_START[] =
  "HTTP/1.1 101 Switching Protocols\n"
  "Upgrade: websocket\n"
  "Connection: upgrade\n";
const char UPGRADE_RESPONSE_ACCEPT_PREFIX[] =
  "Sec-WebSocket-Accept: ";
const char UPGRADE_RESPONSE_END[] =
  "\r\n\r\n";

void decode_hex(const char* hex, uint8_t* out) {
    size_t i_out = 0;
    char hex_byte[3] = {0};
    for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
        hex_byte[0] = hex[i];
        hex_byte[1] = hex[i + 1];
        out[i_out++] = strtol(hex_byte, NULL, 16);
    }
}


char request_buf[MAX_REQUEST_SIZE];

char share_buf[256];



typedef struct {
   union {
       struct {
              uint8_t PAYLOADLEN:7;
              uint8_t MASK:1;
              uint8_t OPCODE:4;
              uint8_t RSV:3;
              uint8_t FIN:1;
       } bits;
       struct {
        uint8_t byte1;
        uint8_t byte0;
       } bytes;
   } meta;
   uint8_t  start;
   uint64_t length;
   union {
       uint32_t maskKey;
    uint8_t  maskBytes[4];
   } mask;
} WebsocketPacketHeader_t;


typedef struct TCP_CLIENT_T_ {
    struct tcp_pcb *pcb;
    size_t conn_id;
    RequestPart current_part; //=METHOD
    size_t current_index;// = 0;

    bool is_upgraded;   // = false;
    bool is_closing;    // =
    size_t request_bytes;// = 0;

    char current_header[HEADER_BUF_SIZE];

    bool has_upgrade_header; //= false;
    bool has_connection_header; //= false;
    bool has_ws_version_header; //= false;
    char ws_key_header_value[HEADER_BUF_SIZE]; // = {0};
    WebsocketPacketHeader_t ws_header;
} TCP_CLIENT_T;

struct tcp_pcb* websocket_pcb = NULL;

TCP_SERVER_T *srv_ctx;


err_t tcp_close_client_connection( void* arg, struct tcp_pcb *client_pcb, err_t close_err) {


    if(websocket_pcb == client_pcb) websocket_pcb = NULL;

    if (client_pcb) {
        tcp_arg(client_pcb, NULL);
        tcp_poll(client_pcb, NULL, 0);
        tcp_sent(client_pcb, NULL);
        tcp_recv(client_pcb, NULL);
        tcp_err(client_pcb, NULL);
        err_t err = tcp_close(client_pcb);
        if (err != ERR_OK) {
            printf("close failed %d, calling abort\n", err);
            tcp_abort(client_pcb);
            close_err = ERR_ABRT;
        }
        if (arg) {
            free(arg);
        }
    }
    return close_err;
}


struct tcp_pcb* init_listen_pcb(uint16_t port, void* arg) {
    cyw43_arch_lwip_check();

    struct tcp_pcb* temp_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!temp_pcb) {
        printf("failed to create temp pcb\n");
        return NULL;
    }

    tcp_arg(temp_pcb, arg);

    if (tcp_bind(temp_pcb, IP_ADDR_ANY, port) != ERR_OK) {
        tcp_abort(temp_pcb);
        printf("failed to bind\n");
            return NULL;
    }

    struct tcp_pcb* listen_pcb = tcp_listen(temp_pcb); //tcp_listen_with_backlog(pcb, 1);
    if (!listen_pcb) {
        tcp_abort(temp_pcb);
        printf("failed to create listen pcb\n");
    }

    // temp_pcb has already been freed
    return listen_pcb;
}


bool flushSend(struct tcp_pcb *pcb) {
    return tcp_output(pcb) == ERR_OK;
}


const u8_t POLL_TIMER_COARSE = 10; // around 5 seconds


extern const char start_page[455];

bool http_handler_process(struct tcp_pcb* pcb, struct pbuf* pb, TCP_CLIENT_T* client_conn) {

    size_t i;

    // Copy the request into the buffer
    pbuf_copy_partial(pb, request_buf, (pb->tot_len > (sizeof(request_buf) - 1)) ? sizeof(request_buf) - 1 : pb->tot_len, 0);

    //METHOD
    if( (request_buf[0]=='G') && (request_buf[1]=='E') && (request_buf[2]=='T') ) {

        if(strncmp(MSFT_CON_TST, request_buf+sizeof(HTTP_GET)+1, sizeof(MSFT_CON_TST) - 1) == 0) {
            tcp_write(pcb, HEADER_CONTINUE_RESPONSE, sizeof(HEADER_CONTINUE_RESPONSE), TCP_WRITE_FLAG_COPY);
        } else if( (request_buf[4]=='/') && (request_buf[5]==' ') && (request_buf[6]=='H') && (request_buf[7]=='T')  && (request_buf[8]=='T')  && (request_buf[9]=='P')) {
            //start page
            //printf(request_buf);

            //i = snprintf(share_buf, sizeof(share_buf), "%s%d\n%s\n", HTML_RESPONSE_START, sizeof(start_page), HTML_RESPONSE_END);
            i = snprintf(share_buf, sizeof(share_buf), "%s%d\n%s", HTML_RESPONSE_START, sizeof(start_page), HTML_RESPONSE_END);
            tcp_write(pcb, share_buf, i, TCP_WRITE_FLAG_COPY);
            //printf(share_buf);

            tcp_write(pcb, start_page, sizeof(start_page), TCP_WRITE_FLAG_COPY);

        } else if( (request_buf[4]=='/') && (request_buf[5]=='i') && (request_buf[6]=='n') && (request_buf[7]=='d')  && (request_buf[8]=='e')  && (request_buf[9]=='x')) {

i = snprintf(share_buf, sizeof(share_buf), HTTP_RESPONSE_HEADERS, 200, sizeof(start_page));
tcp_write(pcb, share_buf, i, TCP_WRITE_FLAG_COPY);
tcp_write(pcb, start_page, sizeof(start_page), TCP_WRITE_FLAG_COPY);

        } else if( (request_buf[4]=='/') && (request_buf[5]=='w') && (request_buf[6]=='e') && (request_buf[7]=='b')  && (request_buf[8]=='s')  && (request_buf[9]=='o') && (request_buf[10]=='c') && (request_buf[11]=='k')  && (request_buf[12]=='e')  && (request_buf[13]=='t') ) {
            //websocket connect
printf(request_buf);
            char *lps, *lpd;
            char combined_key[WS_KEY_COMBINED_BUFFER];// = {0};
            uint8_t sha1[SHA1_SIZE];
            size_t sha1_base64_len;
            uint8_t sha1_base64[SHA1_BASE64_SIZE + 1];
            char ws_key_header_value[64];

            if (!strncmp(request_buf, EXPECTED_HEADER_NAME_WS_KEY, strlen(EXPECTED_HEADER_NAME_WS_KEY))) {
                strcpy(ws_key_header_value, request_buf + strlen(EXPECTED_HEADER_NAME_WS_KEY));
            }

memset(combined_key, 0, sizeof(combined_key));
memset(ws_key_header_value, 0, sizeof(ws_key_header_value));
lps = strstr(request_buf, EXPECTED_HEADER_NAME_WS_KEY) + sizeof(EXPECTED_HEADER_NAME_WS_KEY) - 1;
lpd = ws_key_header_value;

while(*lps!='\n') { *lpd++=*lps++; }

printf("key header val : %s\n", ws_key_header_value);


            strcat(combined_key, ws_key_header_value);
            strcat(combined_key, WS_KEY_MAGIC);

            if (mbedtls_sha1_ret((uint8_t*)combined_key, strlen(combined_key), sha1) != 0) {
                return false;
            }

            if (mbedtls_base64_encode(sha1_base64, sizeof(sha1_base64), &sha1_base64_len, sha1, SHA1_SIZE) != 0) {
                return false;
            }

            sha1_base64[sha1_base64_len] = '\0';
            i = snprintf(share_buf, sizeof(share_buf), "%s%s%s\n", UPGRADE_RESPONSE_START, UPGRADE_RESPONSE_ACCEPT_PREFIX, sha1_base64);
            tcp_write(pcb, share_buf, i, TCP_WRITE_FLAG_COPY);

printf(share_buf);
//tcp_write(pcb, NOT_FOUND_RESPONSE, sizeof(NOT_FOUND_RESPONSE), TCP_WRITE_FLAG_COPY);

            client_conn->is_upgraded = true;
            websocket_pcb = pcb;

            return true;

        } else { printf("other path\n%s", request_buf); tcp_write(pcb, NOT_FOUND_RESPONSE, sizeof(NOT_FOUND_RESPONSE), TCP_WRITE_FLAG_COPY); }

    } else {
printf("none method\n %s", request_buf); tcp_write(pcb, NOT_FOUND_RESPONSE, sizeof(NOT_FOUND_RESPONSE), TCP_WRITE_FLAG_COPY);
    }


    return false;
}


bool ParsePacket(TCP_CLIENT_T* client_conn, char* buffer, uint32_t len)
{
    client_conn->ws_header.meta.bytes.byte0 = (uint8_t) buffer[0];
    client_conn->ws_header.meta.bytes.byte1 = (uint8_t) buffer[1];

    // Payload length
    int payloadIndex = 2;
    client_conn->ws_header.length = client_conn->ws_header.meta.bits.PAYLOADLEN;

    if(client_conn->ws_header.meta.bits.PAYLOADLEN == 126) {
        client_conn->ws_header.length = buffer[2] << 8 | buffer[3];
        payloadIndex = 4;
    }
    
    if(client_conn->ws_header.meta.bits.PAYLOADLEN == 127) {
        client_conn->ws_header.length = buffer[6] << 24 | buffer[7] << 16 | buffer[8] << 8 | buffer[9];
        payloadIndex = 10;
    }

    // Mask
    if(client_conn->ws_header.meta.bits.MASK) {
        client_conn->ws_header.mask.maskBytes[0] = buffer[payloadIndex + 0];
        client_conn->ws_header.mask.maskBytes[0] = buffer[payloadIndex + 1];
        client_conn->ws_header.mask.maskBytes[0] = buffer[payloadIndex + 2];
        client_conn->ws_header.mask.maskBytes[0] = buffer[payloadIndex + 3];
        payloadIndex = payloadIndex + 4;    
        
        // Decrypt    
        for(uint64_t i = 0; i < client_conn->ws_header.length; i++) {
                buffer[payloadIndex + i] = buffer[payloadIndex + i] ^ client_conn->ws_header.mask.maskBytes[i%4];
            }
    }

    // Payload start
    client_conn->ws_header.start = payloadIndex;

    return 0;

}



char websocket_buf[MAX_REQUEST_SIZE];
size_t websocket_rx_len;


bool ws_handler_process(struct tcp_pcb* pcb, struct pbuf* pb, TCP_CLIENT_T* client_conn) {

    size_t i;
    char c;

    if(pb == NULL) {
printf("ws_handler_process pbuf NULL\n");
        return false;
    }

    websocket_rx_len = 0;

    if(pb->tot_len > 0) {
        for (struct pbuf *q = pb; q != NULL; q = q->next) {
            ParsePacket(client_conn, (char *)q->payload, q->len);
            memcpy(websocket_buf+websocket_rx_len, (uint8_t *)q->payload + client_conn->ws_header.start, client_conn->ws_header.length );
            websocket_rx_len += client_conn->ws_header.length;
        }
        tcp_recved(pcb, pb->tot_len);
    }

    return true;
}


bool process(struct tcp_pcb* pcb, struct pbuf* pb, TCP_CLIENT_T* client_conn) {

    bool result = false;

    if(client_conn->is_upgraded) {
        result = ws_handler_process(pcb, pb, client_conn);
    } else {
        result = http_handler_process(pcb, pb, client_conn);
    }

    return result;
}



err_t on_recv(void* arg, struct tcp_pcb* pcb, struct pbuf* pb, err_t err) {
    cyw43_arch_lwip_check();
//    printf("on_recv : ");

    if (!arg) {
        if (pb) {
            printf("pbuf with null arg\n");
            pbuf_free(pb);
        }
        return ERR_OK;
    }

    TCP_CLIENT_T* cli_ctx = (TCP_CLIENT_T*)arg;

    bool ok = false;
    if (pb) {
        ok = process(pcb, pb, cli_ctx);
        tcp_recved(pcb, pb->tot_len);
    }


    if (!ok) {
        tcp_close_client_connection(arg, pcb, ERR_OK);
        //tcp_arg(pcb, NULL);
        //onClose();
        //tcp_close(pcb);
        if (pb) {
            if (tcp_output(pcb) != ERR_OK) {
                printf("tcp_output failed\n");
            }
            printf("closing connection arg 0x%x\n", arg);
        } else {    //remote disconnect
             printf("client closed connection arg 0x%x\n", arg);
        }
    }

    if(pb) pbuf_free(pb);

    return ERR_OK;
}


err_t on_poll(void* arg, struct tcp_pcb* pcb) {
    cyw43_arch_lwip_check();

    printf("on_poll : ");

    if (!arg) {
        tcp_abort(pcb);
        printf("aborting inactive connection with null arg\n");
        return ERR_ABRT;
    }
    printf("arg 0x%x\n", arg);

/*
  ClientConnection* connection = (ClientConnection*)arg;
  if (connection->isClosing()) {
    tcp_arg(pcb, nullptr);
    connection->onClose();
    tcp_abort(pcb);
    DEBUG("aborting inactive connection after close request");
    return ERR_ABRT;
  }
*/

    return ERR_OK;
}

void on_error(void* arg, err_t err) {
    cyw43_arch_lwip_check();

    printf("connection errored %s : ", arg ? "with arg" : "without arg\n");

    if (arg) {
        if(srv_ctx == arg) { printf("on_error srv context\n"); free(arg); srv_ctx = NULL; }
        else printf("arg 0x%x\n", arg);
        //((ClientConnection*)arg)->onClose();
    }
}

static err_t on_connect(void *arg, struct tcp_pcb *new_pcb, err_t err) {
    cyw43_arch_lwip_check();

printf("on_connect : ");

    if (!new_pcb) {
        // Connection error
        printf("null pcb");
        return ERR_ARG;
    }
    if (!arg || err != ERR_OK) {
        // Unexpected error
        tcp_abort(new_pcb);
        printf("aborting %s\n", arg ? "with arg" : "without arg");
        return ERR_ABRT;
    }

    TCP_CLIENT_T* client_ctx = calloc(1, sizeof(TCP_CLIENT_T));

    memset(client_ctx, 0, sizeof(TCP_CLIENT_T));

    client_ctx->current_part = METHOD;

    if (!client_ctx) {
        tcp_abort(new_pcb);
        printf("failed to allocate client_ctx\n");
        return ERR_MEM;//ERR_ABRT;
    }

    tcp_arg(new_pcb, client_ctx);
    tcp_err(new_pcb, on_error);
    tcp_recv(new_pcb, on_recv);
    tcp_poll(new_pcb, on_poll, POLL_TIMER_COARSE);

    printf("success, arg 0x%x\n", client_ctx);

    return ERR_OK;
/*
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    if (err != ERR_OK || client_pcb == NULL) {
        DEBUG_printf("failure in accept\n");
        return ERR_VAL;
    }
    DEBUG_printf("client connected\n");

    // Create the state for the connection
    TCP_CONNECT_STATE_T *con_state = calloc(1, sizeof(TCP_CONNECT_STATE_T));
    if (!con_state) {
        DEBUG_printf("failed to allocate connect state\n");
        return ERR_MEM;
    }
    con_state->pcb = client_pcb; // for checking
    con_state->gw = &state->gw;

    // setup connection to client
    tcp_arg(client_pcb, con_state);
    tcp_sent(client_pcb, tcp_server_sent);
    tcp_recv(client_pcb, tcp_server_recv);
    tcp_poll(client_pcb, tcp_server_poll, POLL_TIME_S * 2);
    tcp_err(client_pcb, tcp_server_err);

    return ERR_OK;
*/
}

enum WebSocketOpCode {
    WEBSOCKET_OPCODE_CONTINUE = 0x0,
    WEBSOCKET_OPCODE_TEXT = 0x1,
    WEBSOCKET_OPCODE_BIN = 0x2,
    WEBSOCKET_OPCODE_CLOSE = 0x8,
    WEBSOCKET_OPCODE_PING = 0x9,
    WEBSOCKET_OPCODE_PONG = 0xA
};

size_t BuildPacket(char* buffer, uint64_t bufferLen, enum WebSocketOpCode opcode, char* payload, uint64_t payloadLen, int mask) {

    int payloadIndex = 2;
    WebsocketPacketHeader_t header;

    if(websocket_pcb == NULL) return 0;
    
    // Fill in meta.bits
    header.meta.bits.FIN = 1;
    header.meta.bits.RSV = 0;
    header.meta.bits.OPCODE = opcode;
    header.meta.bits.MASK = mask;

    // Calculate length
    if(payloadLen < 126) {
        header.meta.bits.PAYLOADLEN = payloadLen;
    } else if(payloadLen < 0x10000) {
        header.meta.bits.PAYLOADLEN = 126;
    } else {
        header.meta.bits.PAYLOADLEN = 127;
    }

    buffer[0] = header.meta.bytes.byte0;
    buffer[1] = header.meta.bytes.byte1;

    // Generate mask
    header.mask.maskKey = (uint32_t)rand();

    // Mask payload
    if(header.meta.bits.MASK) {
            for(uint64_t i = 0; i < payloadLen; i++) {
                payload[i] = payload[i] ^ header.mask.maskBytes[i%4];
            }
      }
    
    // Fill in payload length
    if(header.meta.bits.PAYLOADLEN == 126) {
            buffer[2] = (payloadLen >> 8) & 0xFF;
            buffer[3] = payloadLen & 0xFF;
        payloadIndex = 4;
     }

    if(header.meta.bits.PAYLOADLEN == 127) {
         buffer[2] = (payloadLen >> 56) & 0xFF;
         buffer[3] = (payloadLen >> 48) & 0xFF;
         buffer[4] = (payloadLen >> 40) & 0xFF;
         buffer[5] = (payloadLen >> 32) & 0xFF;
         buffer[6] = (payloadLen >> 24) & 0xFF;
         buffer[7] = (payloadLen >> 16) & 0xFF;
         buffer[8] = (payloadLen >> 8)  & 0xFF;
         buffer[9] = payloadLen & 0xFF;
        payloadIndex = 10;
    }

    // Insert masking key
    if(header.meta.bits.MASK) {
        buffer[payloadIndex] = header.mask.maskBytes[0];
        buffer[payloadIndex + 1] = header.mask.maskBytes[1];
        buffer[payloadIndex + 2] = header.mask.maskBytes[2];
        buffer[payloadIndex + 3] = header.mask.maskBytes[3];
        payloadIndex += 4;
    }

    // Ensure the buffer can handle the packet
    if((payloadLen + payloadIndex) > bufferLen) {
        printf("WEBSOCKET BUFFER OVERFLOW \r\n");
        return 1;
    }

    // Copy in payload
    // memcpy(buffer + payloadIndex, payload, payloadLen);
    for(int i = 0; i < payloadLen; i++) {
        buffer[payloadIndex + i] = payload[i];
    }

    return (payloadIndex + payloadLen);

}




struct tcp_pcb* listen_pcb = NULL;

#include "hardware/rtc.h"
#include "pico/util/datetime.h"


datetime_t t = {0};

volatile size_t alarm_cnt = 0;

static void alarm_callback(void) {
    rtc_get_datetime(&t);
    alarm_cnt++;
}




int main() {

    size_t chk_cnt;

    stdio_init_all();

    srv_ctx = calloc(1, sizeof(TCP_SERVER_T));
    if (!srv_ctx) {
        printf("failed to allocate srv_ctx\n");
        return 1;
    }

    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }
    const char *ap_name = "web_devel_test";
#if 1
    const char *password = "password";
#else
    const char *password = NULL;
#endif

    cyw43_arch_enable_ap_mode(ap_name, password, CYW43_AUTH_WPA2_AES_PSK);

    ip4_addr_t mask;
    IP4_ADDR(ip_2_ip4(&srv_ctx->gw), 192, 168, 4, 1);
    IP4_ADDR(ip_2_ip4(&mask), 255, 255, 255, 0);

    // Start the dhcp server
    dhcp_server_t dhcp_server;
    dhcp_server_init(&dhcp_server, &srv_ctx->gw, &mask);

    // Start the dns server
    dns_server_t dns_server;
    dns_server_init(&dns_server, &srv_ctx->gw);


    cyw43_thread_enter();

    listen_pcb = init_listen_pcb(80, srv_ctx);
    if (listen_pcb) {
        tcp_accept(listen_pcb, on_connect);
    }

    cyw43_thread_exit();

    while(1)  {  cyw43_arch_poll();
        // you can poll as often as you like, however if you have nothing else to do you can
        // choose to sleep until either a specified time, or cyw43_arch_poll() has work to do:
        cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
        if(chk_cnt!=alarm_cnt) {
            chk_cnt = alarm_cnt;
    char datetime_buf[256];
    char *datetime_str = &datetime_buf[0];
    datetime_to_str(datetime_str, sizeof(datetime_buf), &t);
    printf("Alarm Fired At %s\n", datetime_str);

BuildPacket(websocket_buf, sizeof(websocket_buf), WEBSOCKET_OPCODE_TEXT, datetime_str, strlen(datetime_str), 1);

        }
    }
    dns_server_deinit(&dns_server);
    dhcp_server_deinit(&dhcp_server);
    cyw43_arch_deinit();
    return 0;



}



#if 0


#define TCP_PORT 80
#define DEBUG_printf printf
#define POLL_TIME_S 5



#define HTTP_GET "GET"
#define HTTP_RESPONSE_HEADERS "HTTP/1.1 %d OK\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nConnection: close\n\n"
#define LED_TEST_BODY "<html><body><h1>Hello from Pico W.</h1><p>Led is %s</p><p><a href=\"?led=%d\">Turn led %s</a></body></html>"
#define HTTP_RESPONSE_REDIRECT "HTTP/1.1 302 Redirect\nLocation: http://%s" LED_TEST "\n\n"



#define EMPTY_CONTENT_PAGE  "<!DOCTYPE html>\n<html lang=\"en\">\n</html>\n"

const char *HEADER_OK_RESPONSE = "HTTP/1.1 200 OK\nConnection: close\n";
const char *HEADER_FORBIDDEN_RESPONSE = "HTTP/1.1 403 Forbidden\n";
const char *HEADER_NOT_FOUND_RESPONSE = "HTTP/1.1 404 Not Found\n";

const char *HEADER_CONTINUE_RESPONSE = "Expect: 100-continue\n";


/*
GET /connecttest.txt HTTP/1.1
Connection: Close
User-Agent: Microsoft NCSI
Host: www.msftconnecttest.com
*/
#define MSFT_CON_TST    "connecttest"



#define LED_PARAM "led=%d"
#define LED_TEST "/ledtest"
#define LED_GPIO 0



typedef struct TCP_SERVER_T_ {
    struct tcp_pcb *server_pcb;
    bool complete;
    ip_addr_t gw;
} TCP_SERVER_T;

typedef struct TCP_CONNECT_STATE_T_ {
    struct tcp_pcb *pcb;
    int sent_len;
    char headers[128];
    char result[256];
    int header_len;
    int result_len;
    ip_addr_t *gw;
} TCP_CONNECT_STATE_T;

static err_t tcp_close_client_connection(TCP_CONNECT_STATE_T *con_state, struct tcp_pcb *client_pcb, err_t close_err) {
    if (client_pcb) {
        assert(con_state && con_state->pcb == client_pcb);
        tcp_arg(client_pcb, NULL);
        tcp_poll(client_pcb, NULL, 0);
        tcp_sent(client_pcb, NULL);
        tcp_recv(client_pcb, NULL);
        tcp_err(client_pcb, NULL);
        err_t err = tcp_close(client_pcb);
        if (err != ERR_OK) {
            DEBUG_printf("close failed %d, calling abort\n", err);
            tcp_abort(client_pcb);
            close_err = ERR_ABRT;
        }
        if (con_state) {
            free(con_state);
        }
    }
    return close_err;
}

static void tcp_server_close(TCP_SERVER_T *state) {
    if (state->server_pcb) {
        tcp_arg(state->server_pcb, NULL);
        tcp_close(state->server_pcb);
        state->server_pcb = NULL;
    }
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    //DEBUG_printf("***** tx start  %u *****\n", len);
    con_state->sent_len += len;
    if (con_state->sent_len >= con_state->header_len + con_state->result_len) {
        //DEBUG_printf("***** tx end *****\n");
        return tcp_close_client_connection(con_state, pcb, ERR_OK);
    }
    return ERR_OK;
}

static int test_server_content(const char *request, const char *params, char *result, size_t max_result_len) {
    int len = 0;
    if (strncmp(request, LED_TEST, sizeof(LED_TEST) - 1) == 0) {
        // Get the state of the led
        bool value;
        cyw43_gpio_get(&cyw43_state, LED_GPIO, &value);
        int led_state = value;

        // See if the user changed it
        if (params) {
            int led_param = sscanf(params, LED_PARAM, &led_state);
            if (led_param == 1) {
                if (led_state) {
                    // Turn led on
                    cyw43_gpio_set(&cyw43_state, 0, true);
                } else {
                    // Turn led off
                    cyw43_gpio_set(&cyw43_state, 0, false);
                }
            }
        }
        // Generate result
        if (led_state) {
            len = snprintf(result, max_result_len, LED_TEST_BODY, "ON", 0, "OFF");
        } else {
            len = snprintf(result, max_result_len, LED_TEST_BODY, "OFF", 1, "ON");
        }
    }
    return len;
}

err_t tcp_server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    if (!p) {
        DEBUG_printf("connection closed\n");
        return tcp_close_client_connection(con_state, pcb, ERR_OK);
    }
    assert(con_state && con_state->pcb == pcb);
    if (p->tot_len > 0) {
        DEBUG_printf("tcp_server_recv %d err %d\n", p->tot_len, err);
#if 0
        for (struct pbuf *q = p; q != NULL; q = q->next) {
            DEBUG_printf("in: %.*s\n", q->len, q->payload);
        }
#endif
        // Copy the request into the buffer
        pbuf_copy_partial(p, con_state->headers, p->tot_len > sizeof(con_state->headers) - 1 ? sizeof(con_state->headers) - 1 : p->tot_len, 0);


printf(con_state->headers);

        // Handle GET request
        if (strncmp(HTTP_GET, con_state->headers, sizeof(HTTP_GET) - 1) == 0) {
            char *request = con_state->headers + sizeof(HTTP_GET); // + space
            char *params = strchr(request, '?');
            if (params) {
                if (*params) {
                    char *space = strchr(request, ' ');
                    *params++ = 0;
                    if (space) {
                        *space = 0;
                    }
                } else {
                    params = NULL;
                }
            }



            // Generate content
            con_state->result_len = test_server_content(request, params, con_state->result, sizeof(con_state->result));
            //DEBUG_printf("Request: %s?%s\n", request, params);
            //DEBUG_printf("Result: %d\n", con_state->result_len);

            // Check we had enough buffer space
            if (con_state->result_len > sizeof(con_state->result) - 1) {
                DEBUG_printf("Too much result data %d\n", con_state->result_len);
                return tcp_close_client_connection(con_state, pcb, ERR_CLSD);
            }

            // Generate web page


            if(strncmp(MSFT_CON_TST, con_state->headers+sizeof(HTTP_GET)+1, sizeof(MSFT_CON_TST) - 1) == 0) {

                con_state->header_len = snprintf(con_state->headers, sizeof(con_state->headers), HEADER_CONTINUE_RESPONSE);

//                con_state->header_len = snprintf(con_state->headers, sizeof(con_state->headers), HTTP_RESPONSE_HEADERS, 200, sizeof(EMPTY_CONTENT_PAGE));
//                con_state->result_len = snprintf(con_state->result, sizeof(con_state->result), EMPTY_CONTENT_PAGE );

//                con_state->header_len = snprintf(con_state->headers, sizeof(con_state->headers), EMPTY_CONTENT_PAGE, con_state->result_len);
printf(con_state->headers);
printf(("\r\n"));
            } else 

            if (con_state->result_len > 0) {
                con_state->header_len = snprintf(con_state->headers, sizeof(con_state->headers), HTTP_RESPONSE_HEADERS,
                    200, con_state->result_len);
                if (con_state->header_len > sizeof(con_state->headers) - 1) {
                    DEBUG_printf("Too much header data %d\n", con_state->header_len);
                    return tcp_close_client_connection(con_state, pcb, ERR_CLSD);
                }
            } else {
                // Send redirect
                con_state->header_len = snprintf(con_state->headers, sizeof(con_state->headers), HTTP_RESPONSE_REDIRECT,
                    ipaddr_ntoa(con_state->gw));
                //DEBUG_printf("Sending redirect %s", con_state->headers);
            }

//printf("***send***\n%s\n***\n", con_state->headers);



            // Send the headers to the client
            con_state->sent_len = 0;
            err_t err = tcp_write(pcb, con_state->headers, con_state->header_len, 0);
            if (err != ERR_OK) {
                DEBUG_printf("failed to write header data %d\n", err);
                return tcp_close_client_connection(con_state, pcb, err);
            }

            // Send the body to the client
            if (con_state->result_len) {
                err = tcp_write(pcb, con_state->result, con_state->result_len, 0);
                if (err != ERR_OK) {
                    DEBUG_printf("failed to write result data %d\n", err);
                    return tcp_close_client_connection(con_state, pcb, err);
                }
            }
        }
        tcp_recved(pcb, p->tot_len);
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t tcp_server_poll(void *arg, struct tcp_pcb *pcb) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    DEBUG_printf("tcp_server_poll_fn\n");
    return tcp_close_client_connection(con_state, pcb, ERR_OK); // Just disconnect clent?
}

static void tcp_server_err(void *arg, err_t err) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    if (err != ERR_ABRT) {
        DEBUG_printf("tcp_client_err_fn %d\n", err);
        tcp_close_client_connection(con_state, con_state->pcb, err);
    }
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    if (err != ERR_OK || client_pcb == NULL) {
        DEBUG_printf("failure in accept\n");
        return ERR_VAL;
    }
    DEBUG_printf("client connected\n");

    // Create the state for the connection
    TCP_CONNECT_STATE_T *con_state = calloc(1, sizeof(TCP_CONNECT_STATE_T));
    if (!con_state) {
        DEBUG_printf("failed to allocate connect state\n");
        return ERR_MEM;
    }
    con_state->pcb = client_pcb; // for checking
    con_state->gw = &state->gw;

    // setup connection to client
    tcp_arg(client_pcb, con_state);
    tcp_sent(client_pcb, tcp_server_sent);
    tcp_recv(client_pcb, tcp_server_recv);
    tcp_poll(client_pcb, tcp_server_poll, POLL_TIME_S * 2);
    tcp_err(client_pcb, tcp_server_err);

    return ERR_OK;
}

static bool tcp_server_open(void *arg) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    DEBUG_printf("starting server on port %u\n", TCP_PORT);

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb) {
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    err_t err = tcp_bind(pcb, IP_ANY_TYPE, TCP_PORT);
    if (err) {
        DEBUG_printf("failed to bind to port %d\n");
        return false;
    }

    state->server_pcb = tcp_listen_with_backlog(pcb, 1);
    if (!state->server_pcb) {
        DEBUG_printf("failed to listen\n");
        if (pcb) {
            tcp_close(pcb);
        }
        return false;
    }

    tcp_arg(state->server_pcb, state);
    tcp_accept(state->server_pcb, tcp_server_accept);

    return true;
}

int main() {
    stdio_init_all();

    TCP_SERVER_T *state = calloc(1, sizeof(TCP_SERVER_T));
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return 1;
    }

    if (cyw43_arch_init()) {
        DEBUG_printf("failed to initialise\n");
        return 1;
    }
    const char *ap_name = "web_devel_test";
#if 1
    const char *password = "password";
#else
    const char *password = NULL;
#endif

    cyw43_arch_enable_ap_mode(ap_name, password, CYW43_AUTH_WPA2_AES_PSK);

    ip4_addr_t mask;
    IP4_ADDR(ip_2_ip4(&state->gw), 192, 168, 4, 1);
    IP4_ADDR(ip_2_ip4(&mask), 255, 255, 255, 0);

    // Start the dhcp server
    dhcp_server_t dhcp_server;
    dhcp_server_init(&dhcp_server, &state->gw, &mask);

    // Start the dns server
    dns_server_t dns_server;
    dns_server_init(&dns_server, &state->gw);

    if (!tcp_server_open(state)) {
        DEBUG_printf("failed to open server\n");
        return 1;
    }

    while(!state->complete) {
        // the following #ifdef is only here so this same example can be used in multiple modes;
        // you do not need it in your code
#if PICO_CYW43_ARCH_POLL
        // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
        // main loop (not from a timer interrupt) to check for Wi-Fi driver or lwIP work that needs to be done.
        cyw43_arch_poll();
        // you can poll as often as you like, however if you have nothing else to do you can
        // choose to sleep until either a specified time, or cyw43_arch_poll() has work to do:
        cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
#else
        // if you are not using pico_cyw43_arch_poll, then Wi-FI driver and lwIP work
        // is done via interrupt in the background. This sleep is just an example of some (blocking)
        // work you might be doing.
        sleep_ms(1000);
#endif
    }
    dns_server_deinit(&dns_server);
    dhcp_server_deinit(&dhcp_server);
    cyw43_arch_deinit();
    return 0;
}

#endif