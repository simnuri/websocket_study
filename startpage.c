
//extern "C" 
//{

const char start_page[] =
"<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"  <script type=\"text/javascript\">\n"
"    const sock = new WebSocket(`ws://192.168.4.1/websocket`);\n"
"    sock.onopen = () => {\n"
"      console.log('onopen');\n"
"    };\n"
"    sock.onclose = () => {\n"
"      console.log('onclose');\n"
"    };\n"
"    sock.onmessage = (msg) => {\n"
"      console.log('onmessage', msg);\n"
"    };\n"
"    console.log('connecting');\n"
"  </script>\n"
"</head>\n"
"<body>\n"
"  <p>WebSocket server example</p>\n"
"<p id=\"demo\"></p>\n"
"</body>\n"
"</html>\n";

/*
"<script>\n"
"x = 5;\n"
"y = 6;\n"
"z = x + y;\n"
"document.getElementById(\"demo\").innerHTML = \"The value of z is: \" + z;\n"
"</script>\n"
*/


//}

/*
const char start_page[] =
"<html>"
"<head>"
"<title>Hello world!</title>"
"<link rel=\"icon\" href=\"data:;base64,iVBORw0KGgo=\">"
"</head>"
"<body>"
"<h1>This is homepage</h1>"
"</body>"
"</html>";
*/


//const char start_page[] = "<html><body><h1>Hello from Pico W.</h1><p>Led is ON</p><p><a href=\"?led=0\">Turn led OFF</a></body></html>";



#if 0


/* ************************* webchat test ************************* */

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

