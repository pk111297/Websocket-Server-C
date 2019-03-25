function WebSocketTest() 
{
const WebSocket = require('ws');
var ws=new WebSocket("ws://localhost:10000");
ws.onopen = function() 
{
ws.send("Hii I am Pratik");
console.log("Message is sent...");
};
ws.onmessage = function (evt) 
{ 
var received_msg = evt.data;
console.log("Message is received..."+received_msg);
};			
ws.onclose = function() 
{ 
console.log("Connection is closed..."); 
};
}
var ss=new WebSocketTest()
