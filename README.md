# MessageU - Client Server application with Python and C++
This project contains a client software that is used to send encrypted messages between clients on different computers using a model of client-server. </br> 

The **client side** is written in **C++** and has a Command line interface. </br> 
The **server side** is written in **Python** and uses socket for network communication. </br> 

The messages between clients are encrypted from end to end using a symmetric encyption with the **AES encryption protocol**. </br>
In order to transfer the symmetric keys between the clients, there is also an asymmetric enctyption using the **RSA encryption protocol**. </br>

I also used **SQLite database** in the server side in order to store relevant information about the clients that are registered to the server.
The c++ project is dependent on the libraries **boost** and **cryptopp**.</br>
Server side and client side contains each approximately 700 lines of code.

A client can request the following from the server: </br>
<ol>
<li>Register to the server via a registration request.</li>
<li>Send the server it's public key so that anyone can have the oppurtunity to communicate with him securely.</li>
<li>Request from the server all the messages that were sent to him.</li>
<li>Request a symmetric key from a specific client (in order to start messageing him securely).</li>
<li>Send a symmetric key for a specific client.</li>
<li>Send a message.</li>
</ol>
