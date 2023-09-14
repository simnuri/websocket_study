/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause



cmake -G "NMake Makefiles" .. 
nmake 

//set(PICO_BOARD pico_w)
//file(READ static.html PICO_WS_SERVER_STATIC_HTML_HEX HEX)


cmake -S . -B build -G "Unix Makefiles" -DPICO_BOARD=pico_w
cmake --build build -j4

 */

#include <stdio.h>
#include "pico/stdlib.h"

int main() {
    stdio_init_all();
    while (true) {
        printf("Hello, world!\n");
        sleep_ms(1000);
    }
    return 0;
}




#if 0

unsigned char index_html[] = "\
<!DOCTYPE HTML>\
<meta charset=\"utf-8\" />\
<title>WebSocket TEST</title>\
<script language=\"javascript\" type=\"text/javascript\">\
\
	var wsUri = \"ws://192.168.0.165:8080/\";\
	var output;\
\
	function init()\
	{\
		output = document.getElementById(\"output\");\
		testWebSocket();\
	}\
\
	function testWebSocket()\
	{\
		websocket = new WebSocket(wsUri);\
		websocket.onopen = function(evt) { onOpen(evt); };\
		websocket.onclose = function(evt) { onClose(evt); };\
		websocket.onmessage = function(evt) { onMessage(evt); };\
		websocket.onerror = function(evt) { onError(evt); };\
	}\
\
	function onOpen(evt)\
	{\
		writeToScreen(\"Connected\");\
		doSend(\"test message\");\
	}\
\
	function onClose(evt)\
	{\
		writeToScreen(\"DisConnected\");\
	}\
\
	function onMessage(evt)\
	{\
		writeToScreen('<span style=\"color: blue;\">reception: ' + evt.data + '</span>');\
		websocket.close();\
	}\
\
	function onError(evt)\
	{\
		writeToScreen('<span style=\"color: red;\">error:</span>' + evt.data);\
		websocket.close();\
	}\
\
	function doSend(message)\
	{\
		writeToScreen(\"Transmit: \" + message);\
		websocket.send(message);\
	}\
\
	function writeToScreen(message)\
	{\
		var pre = document.createElement(\"p\");\
		pre.style.wordWrap = \"break-word\";\
		pre.innerHTML = message;\
		output.appendChild(pre);\
	}\
\
	window.addEventListener(\"load\", init, false);\
\
</script>\
\
<body>\
	<h2>WebSocket Test</h2>\
	<div id = \"output\"></div>\
</body>\
</html>\0";



const char websocket_resp_msg[] = "\
HTTP/1.1 101 Switching Protocols\r\n\
Server: pado-WebSocketsServer\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Accept: ";

const char websocket_protocol_msg[] = "Sec-WebSocket-Protocol:";


#endif







#if 0


Below is an example of a WebSocket Handshake Request

GET ws://192.168.100.195/ws HTTP/1.1
Host: 192.168.100.195
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Mobile Safari/537.36
Upgrade: websocket
Origin: http://192.168.100.195
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Sec-WebSocket-Key: tnl0nQWIsWwEMpj9V+dV3A==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
The sample WebSocket Handshake Response.

HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: n62Htl716IZqfTO319eJ6Ig1PMI=
Accept-Ranges: none
You would see this WebSocket Protocol Handshake request/response when you open your developer tool and go to the network tab of your browsers. You would see that the status will become 101 Switching Protocols when the HTTP connection is upgraded to a WebSocket connection.




#endif


