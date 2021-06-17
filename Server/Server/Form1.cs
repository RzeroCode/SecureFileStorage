using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;


namespace Server
{


    public partial class Form1 : Form
    {
        bool terminating = false;
        bool listening = false;

        Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        List<Socket> socketList = new List<Socket>();

        //this list is to keep clients in memory
        List<Client> clientList = new List<Client>();

        String selectedDirectory = "";

        String serverPrivatePublicKey;

        BindingList<String> clientBoxList = new BindingList<string>();

        String selectedStorageDirectory = "";

        String requester;

        String requesterFileName;
        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
            clientBox.DataSource = clientBoxList;
        }

        private void button_Listen_Click_1(object sender, EventArgs e)
        {
            int serverPort;
            if (Int32.TryParse(textBox_Port.Text, out serverPort))
            {
                if (serverPort > 65536)
                {
                    logs.AppendText("Invalid port number.\n");
                    return;
                }
                serverSocket.Bind(new IPEndPoint(IPAddress.Any, serverPort));
                serverSocket.Listen(50);


                Thread acceptThread = new Thread(Accept);
                acceptThread.Start();
                listening = true;
                button_Listen.Enabled = false;
                button_browse.Enabled = false;

                logs.AppendText("\nStarted listening on port: " + serverPort + "\n");
            }
            else
            {
                logs.AppendText("Please check port number \n");
            }
        }

        private void Accept()
        {
            while (listening)
            {
                Client client = new Client();
                try
                {
                    Socket newClient = serverSocket.Accept();
                    //newClient.ReceiveTimeout = 5000;

                    //recieve username
                    Byte[] buffer_username = new Byte[64];
                    newClient.Receive(buffer_username);
                    string username = Encoding.Default.GetString(buffer_username);
                    username = username.Substring(0, username.IndexOf("\0"));

                    //username shouldn't contain this
                    if (username.Contains("_"))
                    {
                        Byte[] buffer = new Byte[64];
                        buffer = Encoding.Default.GetBytes("Error: username cannot contain \"_\" \n");
                        newClient.Send(buffer);
                    }

                    bool x = true;
                    //if client already connected with the same name, disconnect
                    foreach (var user in clientList)
                    {
                        if (user.name == username)
                        {
                            //TODO: give correct warning to log and client
                            Byte[] buffer = new Byte[64];
                            buffer = Encoding.Default.GetBytes("Error: a client with " + username + " has already connected.\n");
                            newClient.Send(buffer);
                            x = false;
                            //newClient.Close();
                            //newClient.Shutdown(SocketShutdown.Both);
                        }
                    }
                    if (x == false)
                    {
                        continue;
                    }
                    //send that connection is succesfull
                    Byte[] bufferX = new Byte[64];
                    bufferX = Encoding.Default.GetBytes("Success!! You have been connected.\n");
                    newClient.Send(bufferX);

                    logs.AppendText("Success!! A new user connected: " + username + "\n");


                    client.name = username;
                    client.socket = newClient;
                    clientList.Add(client);
                    clientBoxList.Add(client.name);

                    socketList.Add(newClient);

                    Thread receiveThread = new Thread(() => Receive(client.socket, client));
                    receiveThread.Start();
                }
                catch
                {
                    if (terminating)
                    {
                        listening = false;
                    }
                    else
                    {
                        logs.AppendText("The client's socket stopped working. Shutting down connection.\n");
                    }
                    // TODO: delete client from list
                    removeClient(client);
                }
            }
        }


        private void Receive(Socket socket, Client client)
        {
            bool connected = true;
            try
            {

                //load the perspective client public key
                String clientPublicKey = "";
                string[] fileEntries = Directory.GetFiles(selectedDirectory);
                foreach (string fileName in fileEntries)
                {
                    String file = Path.GetFileName(fileName);
                    file = file.Split('_')[0];
                    if (file.Equals(client.name)) //if file name is: c1_pub.txt, split and get first index: c1
                    {
                        using (System.IO.StreamReader fileReader = new System.IO.StreamReader(fileName))
                        {
                            clientPublicKey = Encoding.Default.GetString(Encoding.Default.GetBytes(fileReader.ReadToEnd()));
                            client.public_key = clientPublicKey;
                            for (int i = 0; i < clientList.Count; i++)
                            {
                                if (clientList[i].name.Equals(client.name))
                                {
                                    clientList[i].public_key = client.public_key;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }

                if (clientPublicKey.Equals(""))//if the file is not found return
                {
                    //TODO send appropiate message
                    removeClient(client);
                    logs.AppendText(client.name + "'s key could not be found. Disconnecting client...\n");
                    //socket.Shutdown(SocketShutdown.Both);
                    socketList.Remove(socket);
                    connected = false;
                    return;
                }



                //produce random nonce
                byte[] nonce_128 = new byte[16];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(nonce_128);
                }
                //send random nonce
                socket.Send(nonce_128);
                logs.AppendText($"128-bit nonce has been sent to {client.name} : { generateHexStringFromByteArray(nonce_128) }\n");

                //recieve client's signed nonce
                Byte[] buffer_client_signed_RSA = new Byte[512];
                socket.Receive(buffer_client_signed_RSA);
                logs.AppendText($"Sign recieved from client { generateHexStringFromByteArray(buffer_client_signed_RSA) }\n");

                //produce random nonce for HMAC
                byte[] nonce_256 = new byte[32];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(nonce_256);
                }

                logs.AppendText($"Nonce produced { generateHexStringFromByteArray(nonce_256) }\n");


                //verify the signed nonce
                //USE PUBLIC KEY HERE (IN OUR CASE IT IS SELECTED AUTO, SINCE WE HAVE PUBLIC AND PRIVATE IN XML)
                bool verificationResult = verifyWithRSA(Encoding.Default.GetString(nonce_128), 4096, clientPublicKey, buffer_client_signed_RSA);
                if (verificationResult == true)
                {
                    logs.AppendText("Valid signature from " + client.name + "\n");
                    //encrypt the nonce(HMAC key) with client's public RSA
                    String enc_HMAC_key_RSA4096 = Encoding.Default.GetString(encryptWithRSA(Encoding.Default.GetString(nonce_256), 4096, clientPublicKey));
                    //------------------------------------------------------------------------------------------------------------------
                    //------------------------------------------------------------------------------------------------------------------
                    client.HMAC_key = generateHexStringFromByteArray(nonce_256);

                    for (int i = 0; i < clientList.Count; i++)
                    {
                        if (clientList[i].name.Equals(client.name))
                        {
                            clientList[i].HMAC_key = client.HMAC_key;
                            break;
                        }
                    }
                    //------------------------------------------------------------------------------------------------------------------
                    //------------------------------------------------------------------------------------------------------------------

                    String positive_mess = "Ack1";
                    String finalMessage = enc_HMAC_key_RSA4096 + positive_mess;

                    //sign enc_HMAC + positive message, then send it
                    byte[] signed_HMAC_key = signWithRSA(finalMessage, 4096, serverPrivatePublicKey);
                    //socket.Send(signed_HMAC_key);

                    //send positive message
                    byte[] pos_mes = Encoding.Default.GetBytes(positive_mess);
                    //socket.Send(y);

                    //send encrypted HMAC key
                    byte[] enc_hmac_key = Encoding.Default.GetBytes(enc_HMAC_key_RSA4096);
                    //socket.Send(x);


                    byte[] merged_message = new byte[1028];
                    Array.Copy(signed_HMAC_key, 0, merged_message, 0, 512);
                    Array.Copy(pos_mes, 0, merged_message, 512, 4);
                    Array.Copy(enc_hmac_key, 0, merged_message, 516, 512);

                    socket.Send(merged_message);

                    logs.AppendText("Client " + client.name + " has been authenticated. Positive Acknowledgement sent.\n");
                    logs.AppendText("These were sent:\n-Signed HMAC key: " + generateHexStringFromByteArray(signed_HMAC_key) + "\n -Positive acknowledgment: " +
                        generateHexStringFromByteArray(pos_mes) + "\n -Encrypted HMAC key: " + generateHexStringFromByteArray(enc_hmac_key) + "\n");
                }
                else
                {
                    logs.AppendText("Invalid signature from " + client.name + "\n");
                    //encrypt the nonce(HMAC key) with client's public RSA
                    String enc_HMAC_key_RSA4096 = Encoding.Default.GetString(encryptWithRSA(Encoding.Default.GetString(nonce_256), 4096, clientPublicKey));
                    client.HMAC_key = enc_HMAC_key_RSA4096;
                    for (int i = 0; i < clientList.Count; i++)
                    {
                        if (clientList[i].name.Equals(client.name))
                        {
                            clientList[i].HMAC_key = client.HMAC_key;
                            break;
                        }
                    }
                    String positive_mess = "Ack0";
                    String finalMessage = enc_HMAC_key_RSA4096 + positive_mess;

                    //sign enc_HMAC + positive message, then send it
                    byte[] signed_HMAC_key = signWithRSA(finalMessage, 4096, serverPrivatePublicKey);
                    //socket.Send(signed_HMAC_key);

                    //send positive message
                    byte[] pos_mes = Encoding.Default.GetBytes(positive_mess);
                    //socket.Send(y);

                    //send encrypted HMAC
                    byte[] enc_hmac_key = Encoding.Default.GetBytes(enc_HMAC_key_RSA4096);
                    //socket.Send(x);


                    byte[] merged_message = new byte[1028];
                    Array.Copy(signed_HMAC_key, 0, merged_message, 0, 512);
                    Array.Copy(pos_mes, 0, merged_message, 512, 4);
                    Array.Copy(enc_hmac_key, 0, merged_message, 516, 512);

                    socket.Send(merged_message);

                    logs.AppendText("Client " + client.name + " has NOT been authenticated. Negative Acknowledgement sent.\n");
                    logs.AppendText("These were sent:\n-Signed HMAC key: " + generateHexStringFromByteArray(signed_HMAC_key) + "\n -Negative acknowledgment: " +
                        generateHexStringFromByteArray(pos_mes) + "\n -Encrypted HMAC key: " + generateHexStringFromByteArray(enc_hmac_key) + "\n");

                    //TODO close the connection
                    //clientList.Remove(client);
                    //clientBoxList.Remove(client.name);
                    removeClient(client);
                    logs.AppendText("Client " + client.name + " has disconnected.\n");
                    //socket.Shutdown(SocketShutdown.Both);
                    socketList.Remove(socket);
                    connected = false;
                }

            }
            catch (Exception e)
            {
                logs.AppendText("There was an error with the client, " + client.name + " is now disconnected\n");
                removeClient(client);
                //socket.Shutdown(SocketShutdown.Both);
                socketList.Remove(socket);
                //clientList.Remove(client);
                //clientBoxList.Remove(client.name);
                connected = false;
            }


            //if (socket.Poll(1000, SelectMode.SelectRead))
            //    throw new Exception();
            logs.AppendText("====Now listening!!!!====\n");

            while (connected && !terminating)
            {
                try
                {
                    //recieve the file length
                    Byte[] bufferInit = new Byte[65000];
                    socket.Receive(bufferInit);
                    if (bufferInit[0] == (Encoding.Default.GetBytes("1")[0]))
                    {
                        Byte[] buffer = new Byte[128];
                        Array.Copy(bufferInit, 1, buffer, 0, 127);

                        string incomingMessageLength = Encoding.Default.GetString(buffer);
                        incomingMessageLength = incomingMessageLength.Substring(0, incomingMessageLength.IndexOf("\0"));
                        int incomingMessageLengthInt32 = Int32.Parse(incomingMessageLength);
                        logs.AppendText("\nFor user " + client.name + ", HMAC Session Key found: \n" + client.HMAC_key);


                        //recieve actual file
                        if (incomingMessageLengthInt32 < 65000)
                        {
                            Byte[] encrpytedFileContent = new Byte[incomingMessageLengthInt32];
                            socket.Receive(encrpytedFileContent);
                            //Get HMAC of encrypted file and encrypted file
                            byte[] HMAC_enc_file = new byte[64];
                            byte[] enc_file = new byte[incomingMessageLengthInt32 - 64];
                            Array.Copy(encrpytedFileContent, 0, HMAC_enc_file, 0, 64);
                            Array.Copy(encrpytedFileContent, 64, enc_file, 0, incomingMessageLengthInt32 - 64);
                            //logs.AppendText($"\nEncrypted file: {generateHexStringFromByteArray(enc_file)}\n");
                            logs.AppendText($"\nHMAC of encrypted file: {generateHexStringFromByteArray(HMAC_enc_file)}\n");

                            byte[] hmac_val = FILE_applyHMACwithSHA512(enc_file, hexStringToByteArray(client.HMAC_key));
                            if (Encoding.Default.GetString(hmac_val) == Encoding.Default.GetString(HMAC_enc_file)) // file encryption verified
                            {
                                logs.AppendText($"\nUploaded file verified using shared HMAC key {client.HMAC_key} and accepted for user: " + client.name);
                                //TODO: Get current directory from system
                                String path = selectedStorageDirectory;
                                String filename = client.name + "_";
                                int index = -1;
                                do
                                {
                                    index++;
                                } while (File.Exists(path + "\\" + filename + index.ToString()));
                                filename += index.ToString();

                                logs.AppendText("\nAssigned filename of uploaded file is: " + filename + "\n");
                                File.WriteAllBytes(path + "\\" + filename, enc_file);
                                logs.AppendText("\nSaved file location: " + path + "\n");
                                logs.AppendText("\nPositive Acknowledgement and Assigned Filename is sending...\n");

                                //--------------------------------------------------------------------------------------------------------------

                                String pos_ack_filename = "UPL_ACK1" + filename;
                                byte[] pos_ack_filename_ = Encoding.Default.GetBytes(pos_ack_filename + "*");
                                logs.AppendText($"\nPositive acknowledge+filename: {generateHexStringFromByteArray(pos_ack_filename_)}\n");
                                byte[] signed_ack_filename = signWithRSA(pos_ack_filename, 4096, serverPrivatePublicKey);
                                logs.AppendText($"\nSigned version of Positive acknowledge+filename: {generateHexStringFromByteArray(signed_ack_filename)}\n");
                                byte[] merged_message = new byte[pos_ack_filename_.Length + signed_ack_filename.Length];
                                //Array.Copy(pos_ack_filename_, 0, merged_message, 0, pos_ack_filename_.Length);
                                //Array.Copy(signed_ack_filename, 0, merged_message, pos_ack_filename_.Length, 512);
                                Array.Copy(pos_ack_filename_, 0, merged_message, 0, pos_ack_filename_.Length);
                                Array.Copy(signed_ack_filename, 0, merged_message, pos_ack_filename_.Length, signed_ack_filename.Length);

                                logs.AppendText($"\nSent message: {generateHexStringFromByteArray(merged_message)} to {client.name}\n");

                                socket.Send(merged_message);

                                logs.AppendText("Sent!\n");

                            }
                            else //not verified
                            {
                                logs.AppendText("\nHMAC does not match, Uploaded file is NOT verified for user" + client.name);
                                logs.AppendText("\nNegative Acknowledgement is sending... ");

                                String neg_ack_file = "UPL_ACK0";
                                byte[] signed_ack_filename = signWithRSA(neg_ack_file, 4096, serverPrivatePublicKey);
                                socket.Send(signed_ack_filename);
                                logs.AppendText($"\nNegative acknowledgement sent: {generateHexStringFromByteArray(signed_ack_filename)}\n");

                                logs.AppendText("Sent!\n");
                            }
                        }
                        else
                        {

                        }
                    }
                    else if (bufferInit[0] == (Encoding.Default.GetBytes("0")[0])) //download request
                    {
                        Byte[] signedFileName = new Byte[512];
                        Byte[] fileName = new Byte[300];

                        Array.Copy(bufferInit, 1, signedFileName, 0, 512);
                        Array.Copy(bufferInit, 513, fileName, 0, 300);
                        logs.AppendText($"\nSigned filename: {generateHexStringFromByteArray(signedFileName)}\n");


                        String fName = Encoding.Default.GetString(fileName);
                        fName = fName.Substring(0, fName.IndexOf("\0"));
                        //logs.AppendText($"\filename: {fName}\n");

                        bool verificationResult = verifyWithRSA(fName, 4096, client.public_key, signedFileName);
                        if (verificationResult)
                        {
                            logs.AppendText($"\n{client.name} sign is verified");
                            String ownerName = fName.Split('_')[0];
                            bool ownerExists = false;
                            foreach (Client c in clientList)
                            {
                                if (c.name.Equals(ownerName))
                                    ownerExists = true;

                            }
                            if (File.Exists(selectedStorageDirectory + "\\" + fName))
                            {
                                if (ownerExists)
                                {
                                    if (ownerName.Equals(client.name))
                                    {
                                        String message = "OFil_Ack";        //owner of the file is requesting
                                        byte[] enc_file = File.ReadAllBytes(selectedStorageDirectory + "\\" + fName);
                                        //logs.AppendText($"\nEncrypted {fName}: {generateHexStringFromByteArray(enc_file)}\n");
                                        byte[] signed_enc_file = signWithRSA(Encoding.Default.GetString(enc_file), 4096, serverPrivatePublicKey);
                                        //logs.AppendText($"\nSigned encrypted {fName}: \n");
                                        byte[] mes = Encoding.Default.GetBytes(message);

                                        byte[] merged_message = new byte[enc_file.Length + signed_enc_file.Length + mes.Length];

                                        Array.Copy(mes, 0, merged_message, 0, mes.Length);
                                        Array.Copy(signed_enc_file, 0, merged_message, mes.Length, signed_enc_file.Length);  //what happens if file is large
                                        Array.Copy(enc_file, 0, merged_message, mes.Length + signed_enc_file.Length, enc_file.Length);

                                        logs.AppendText("\nOwner is requesting the file: " + fName);
                                        logs.AppendText("\nFile is sent to the: " + client.name);

                                        String m2 = message + enc_file.Length.ToString();

                                        socket.Send(Encoding.Default.GetBytes(m2));
                                        logs.AppendText($"\nSent ACK message: {generateHexStringFromByteArray(Encoding.Default.GetBytes(m2))}\n");
                                        logs.AppendText($"\nSent signed encyrpted file: {generateHexStringFromByteArray(signed_enc_file)}\n");

                                        socket.Send(merged_message);
                                        logs.AppendText($"\nSent ACK + signed encrypted file + encrypted file is sent to {client.name}\n");

                                        logs.AppendText("\nSent!\n");


                                    }
                                    else  //file relaying protocol starts here
                                    {
                                        requester = client.name;
                                        requesterFileName = fName;
                                        foreach (Client c in clientList)
                                        {
                                            if (c.name.Equals(ownerName))
                                            {
                                                // filename + requester name + requester public key
                                                byte[] ack = Encoding.Default.GetBytes("RLY_ACK1");
                                                String merged_m = fName + "*" + client.name + "!" + client.public_key;
                                                byte[] mergedmess = Encoding.Default.GetBytes(merged_m);
                                                byte[] hmac_merged = applyHMACwithSHA512(merged_m, hexStringToByteArray(c.HMAC_key));
                                                byte[] mergedmess_final = new byte[mergedmess.Length + hmac_merged.Length + ack.Length];

                                                Array.Copy(ack, 0, mergedmess_final, 0, ack.Length);
                                                Array.Copy(hmac_merged, 0, mergedmess_final, ack.Length, hmac_merged.Length);
                                                Array.Copy(mergedmess, 0, mergedmess_final, ack.Length + hmac_merged.Length, mergedmess.Length);

                                                logs.AppendText("\nRequester is not the same as the owner, file relaying protocol starts for file: " + fName + ".Requester is: " + requester + ".Owner is: " + ownerName + ".\n");

                                                c.socket.Send(mergedmess_final);
                                                logs.AppendText($"\nSent message to {c.name}: filename:{fName}, client name: {client.name}, \nclient public key{client.public_key} \nand  HMAC{generateHexStringFromByteArray(hmac_merged)}\n");

                                                logs.AppendText("\nFilename,requesting client's name and requester's public key is sent to the owner... \n");
                                                logs.AppendText($"\nThe HMAC key used was {c.name}'s key which is {c.HMAC_key} ");

                                                break;
                                            }
                                        }

                                    }
                                }
                                else
                                {
                                    logs.AppendText("\nOwner not connected to the server,request from: " + client.name);
                                    logs.AppendText("\nNegative Acknowledgement is sending... ");

                                    String neg_ack = "ONA_Ack0"; //owner not exists
                                    byte[] neg_mes = Encoding.Default.GetBytes(neg_ack);
                                    byte[] signed_ack = signWithRSA(neg_ack, 4096, serverPrivatePublicKey);
                                    byte[] merged_message = new byte[neg_mes.Length + signed_ack.Length];

                                    Array.Copy(neg_mes, 0, merged_message, 0, neg_mes.Length);
                                    Array.Copy(signed_ack, 0, merged_message, neg_mes.Length, signed_ack.Length);

                                    socket.Send(merged_message);
                                    logs.AppendText($"\nSent message: {generateHexStringFromByteArray(merged_message)}\n");

                                    logs.AppendText("Sent!\n");
                                }
                            }
                            else
                            {
                                logs.AppendText("\nFile not exists from request of: " + client.name);
                                logs.AppendText("\nNegative Acknowledgement is sending... ");

                                String neg_ack = "FNA_Ack0"; //file not exists
                                byte[] neg_mes = Encoding.Default.GetBytes(neg_ack);
                                byte[] signed_ack = signWithRSA(neg_ack, 4096, serverPrivatePublicKey);
                                byte[] merged_message = new byte[neg_mes.Length + signed_ack.Length];

                                Array.Copy(neg_mes, 0, merged_message, 0, neg_mes.Length);
                                Array.Copy(signed_ack, 0, merged_message, neg_mes.Length, signed_ack.Length);

                                socket.Send(merged_message);
                                logs.AppendText($"\nSent message: {generateHexStringFromByteArray(merged_message)}\n");

                                logs.AppendText("Sent!\n");
                            }
                        }
                        else
                        {
                            logs.AppendText("\nDownload request denied from: " + client.name);
                            logs.AppendText("\nCouldn't verify the signature, negative Acknowledgement is sending... ");

                            String neg_ack = "FDN_Ack0"; //file denied
                            byte[] neg_mes = Encoding.Default.GetBytes(neg_ack);
                            byte[] signed_ack = signWithRSA(neg_ack, 4096, serverPrivatePublicKey);
                            byte[] merged_message = new byte[neg_mes.Length + signed_ack.Length];

                            Array.Copy(neg_mes, 0, merged_message, 0, neg_mes.Length);
                            Array.Copy(signed_ack, 0, merged_message, neg_mes.Length, signed_ack.Length);


                            socket.Send(merged_message);

                            logs.AppendText($"\nSent message: {generateHexStringFromByteArray(merged_message)}\n");
                            logs.AppendText("Sent!\n");

                        }

                    }
                    else if (bufferInit[0] == (Encoding.Default.GetBytes("2")[0]))
                    {
                        byte[] signat = new byte[512];
                        Array.Copy(bufferInit, 1, signat, 0, 512);
                        bool verificationResult = verifyWithRSA("2", 4096, client.public_key, signat);
                        if (verificationResult)
                        {
                            logs.AppendText("\nDuring relaying: HMAC was not verified by the owner, negative message is verified with signature");
                        }
                        else
                        {
                            logs.AppendText("\nDuring relaying: HMAC was not verified by the owner, negative message is NOT verified with signature");

                        }
                    }
                    else if (bufferInit[0] == (Encoding.Default.GetBytes("3")[0])) //relay is granted by the owner
                    {
                        String incomingMessageLength = Encoding.Default.GetString(bufferInit);
                        incomingMessageLength = incomingMessageLength.Substring(1, incomingMessageLength.IndexOf("\0"));
                        int enc_rsa_length = Int32.Parse(incomingMessageLength);
                        Byte[] actual_buffer = new Byte[10000];
                        socket.Receive(actual_buffer);

                        byte[] hmac_check = new byte[64];
                        Array.Copy(actual_buffer, 1, hmac_check, 0, hmac_check.Length);
                        logs.AppendText($"\nHMAC Received: {generateHexStringFromByteArray(hmac_check)}\n");
                        


                        byte[] enc_rsa = new byte[enc_rsa_length];
                        Array.Copy(actual_buffer, 1 + hmac_check.Length, enc_rsa, 0, enc_rsa.Length);
                        logs.AppendText($"\nRecieved RSA encryption: {generateHexStringFromByteArray(enc_rsa)}\n");

                        String enc_rsa_str = Encoding.Default.GetString(enc_rsa);

                        byte[] apply_hmac = applyHMACwithSHA512("3" + enc_rsa_str, hexStringToByteArray(client.HMAC_key));

                        if (Encoding.Default.GetString(hmac_check).Equals(Encoding.Default.GetString(apply_hmac)))
                        {
                            logs.AppendText("\nHMAC is verified\n");
                            logs.AppendText("\nPermission is given by the owner\n");
                            logs.AppendText($"\nSending the encrypted file({requesterFileName}) and keys to decrypt it to: " + requester + "...\n");

                            foreach (Client c in clientList)
                            {
                                if (c.name.Equals(requester))
                                {
                                    byte[] enc_file = File.ReadAllBytes(selectedStorageDirectory + "\\" + requesterFileName);
                                    logs.AppendText("\nFile is found at: " + selectedStorageDirectory + "\\" + requesterFileName);
                                    
                                    byte[] sign = new byte[enc_rsa.Length + enc_file.Length];
                                    Array.Copy(enc_rsa, 0, sign, 0, enc_rsa.Length);
                                    Array.Copy(enc_file, 0, sign, enc_rsa.Length, enc_file.Length);

                                    byte[] merged_sign = signWithRSA(Encoding.Default.GetString(sign), 4096, serverPrivatePublicKey);
                                    logs.AppendText($"\nSigning Recieved RSA encryption and the content of encrypted file: {generateHexStringFromByteArray(merged_sign)}");


                                    String pos_ack = "FIN_Ack1";
                                    byte[] pos_ack_byte = Encoding.Default.GetBytes(pos_ack);
                                    byte[] merge = new byte[pos_ack.Length + merged_sign.Length + enc_rsa.Length + enc_file.Length];
                                    Array.Copy(pos_ack_byte, 0, merge, 0, pos_ack_byte.Length);
                                    Array.Copy(merged_sign, 0, merge, pos_ack_byte.Length, merged_sign.Length);
                                    Array.Copy(enc_rsa, 0, merge, pos_ack_byte.Length + merged_sign.Length, enc_rsa.Length);
                                    Array.Copy(enc_file, 0, merge, pos_ack_byte.Length + merged_sign.Length + enc_rsa.Length, enc_file.Length);
                                    
                                    String m2 = pos_ack + enc_rsa_length.ToString() + "|" + enc_file.Length.ToString();

                                    c.socket.Send(Encoding.Default.GetBytes(m2));
                                    logs.AppendText($"\nSent lengths message to {c.name}: {generateHexStringFromByteArray(Encoding.Default.GetBytes(m2))}\n");


                                    c.socket.Send(merge);
                                    logs.AppendText($"\nThese will be sent to {c.name}: \n");
                                    logs.AppendText($"\nPositive ACK {generateHexStringFromByteArray(pos_ack_byte)} \n");
                                    logs.AppendText($"\nSign(Recieved RSA encryption & the content of encrypted file) {generateHexStringFromByteArray(merged_sign)} \n");
                                    logs.AppendText($"\nRecieved RSA encryption {generateHexStringFromByteArray(enc_rsa)} \n");
                                    logs.AppendText($"\nAnd encyrpted file (not shown here because of IU complexity))\n");


                                    break;
                                }
                            }
                        }
                        else
                        {
                            logs.AppendText("\nHMAC is NOT verified, ending protocol...");
                        }

                    }
                    else if (bufferInit[0] == (Encoding.Default.GetBytes("4")[0])) //relay is rejected by the owner
                    {
                        byte[] hmac_check = new byte[64];
                        Array.Copy(bufferInit, 1, hmac_check, 0, hmac_check.Length);

                        logs.AppendText("\nRecieved negative ACK from owner. Comparing the ACK and its HMAC...");
                        logs.AppendText($"\nRecieved HMAC: {generateHexStringFromByteArray(hmac_check)}");

                        byte[] apply_hmac = applyHMACwithSHA512("4", hexStringToByteArray(client.HMAC_key));
                        logs.AppendText($"\nPorduced HMAC from ACK HMAC: {generateHexStringFromByteArray(apply_hmac)}");


                        if (Encoding.Default.GetString(hmac_check).Equals(Encoding.Default.GetString(apply_hmac)))
                        {
                            logs.AppendText("\nHMAC is verified\n");
                            logs.AppendText("\nPermission is NOT GRANTED by the owner!!!\n");
                            String neg_ack = "FIN_Ack0";

                            byte[] neg_mes = Encoding.Default.GetBytes(neg_ack);
                            byte[] signed_ack = signWithRSA(neg_ack, 4096, serverPrivatePublicKey);
                            byte[] merged_message = new byte[neg_mes.Length + signed_ack.Length];

                            Array.Copy(neg_mes, 0, merged_message, 0, neg_mes.Length);
                            Array.Copy(signed_ack, 0, merged_message, neg_mes.Length, signed_ack.Length);

                            foreach (Client c in clientList)
                            {
                                if (c.name.Equals(requester))
                                {

                                    c.socket.Send(merged_message);
                                    logs.AppendText($"\nSigning negative ACK: {generateHexStringFromByteArray(signed_ack)}\n");
                                    logs.AppendText($"\nSent negative ack + sign to requester: {c.name}: {generateHexStringFromByteArray(merged_message)}\n");
                                    break;
                                }
                            }
                            

                            logs.AppendText("\nNegative permission message is sent to the requester!!!\n");


                        }
                        else
                        {
                            logs.AppendText("\nHMAC is NOT verified, ending protocol...");
                        }
                    }
                }
                catch
                {
                    if (!terminating)
                    {
                        logs.AppendText("\n" + client.name + " has disconnected\n");
                    }

                    // delete client from list
                    clientList.Remove(client);
                    clientBoxList.Remove(client.name);
                    removeClient(client);
                    //socket.Shutdown(SocketShutdown.Both);
                    socketList.Remove(socket);
                    connected = false;
                    return;
                }
            }
        }
        private void removeClient(Client client)
        {
            if (client.socket != null) client.socket.Shutdown(SocketShutdown.Both);
            //clientList.Remove(client);

            for (int i = 0; i < clientList.Count; i++)
            {
                if (client.name == clientList[i].name)
                {
                    clientList.RemoveAt(i);

                    break;
                }
            }
            clientBoxList.Remove(client.name);
        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            foreach (var client in clientList)
            {
                //client.socket.Shutdown(SocketShutdown.Both);
                client.socket.Close();
            }
            listening = false;
            terminating = true;
            Environment.Exit(0);
        }



        private void button_browse_Click(object sender, EventArgs e)
        {
            if (listening)
            {
                return;
            }
            FolderBrowserDialog folderDlg = new FolderBrowserDialog();
            folderDlg.ShowNewFolderButton = true;
            // Show the FolderBrowserDialog.  
            DialogResult result = folderDlg.ShowDialog();
            if (result == DialogResult.OK)
            {
                selectedDirectory = folderDlg.SelectedPath;

            }
            string[] fileEntries;
            try
            {
                fileEntries = Directory.GetFiles(selectedDirectory);
            }
            catch (Exception)
            {
                logs.AppendText("You did not select a proper directory for the keys.\n");
                return;

            }
            foreach (string fileName in fileEntries)
            {
                String file = Path.GetFileName(fileName);

                if (file.Equals("server_pub_prv.txt"))
                {
                    using (System.IO.StreamReader fileReader = new System.IO.StreamReader(fileName))
                    {
                        serverPrivatePublicKey = Encoding.Default.GetString(Encoding.Default.GetBytes(fileReader.ReadToEnd()));
                    }
                    logs.AppendText("Found file path: " + fileName);
                    button_Listen.Enabled = true;
                    return;
                }
            }
            logs.AppendText("\nNo private/public key is found\n");

        }

        //select storage folder
        private void button_storage_Click(object sender, EventArgs e)
        {
            if (listening)
            {
                return;
            }
            FolderBrowserDialog folderDlg = new FolderBrowserDialog();
            folderDlg.ShowNewFolderButton = true;
            // Show the FolderBrowserDialog.  
            DialogResult result = folderDlg.ShowDialog();
            if (result == DialogResult.OK)
            {
                selectedStorageDirectory = folderDlg.SelectedPath;

            }
            logs.AppendText("\nStorage folder is: " + selectedStorageDirectory + "\n");
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void richTextBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void folderBrowserDialog1_HelpRequest(object sender, EventArgs e)
        {

        }


        // helper functions
        //generates hex string for the keys


        static byte[] FILE_applyHMACwithSHA512(byte[] byteInput, byte[] key)
        {
            // convert input string to byte array
            //byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA512 hmacSHA512 = new HMACSHA512(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA512.ComputeHash(byteInput);

            return result;
        }

        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }

        public static byte[] hexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        /*    HASH    */

        // hash function: SHA-256
        static byte[] hashWithSHA256(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA256CryptoServiceProvider sha256Hasher = new SHA256CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha256Hasher.ComputeHash(byteInput);

            return result;
        }

        // hash function: SHA-384
        static byte[] hashWithSHA384(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA384CryptoServiceProvider sha384Hasher = new SHA384CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha384Hasher.ComputeHash(byteInput);

            return result;
        }

        // hash function: SHA-512
        static byte[] hashWithSHA512(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA512CryptoServiceProvider sha512Hasher = new SHA512CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha512Hasher.ComputeHash(byteInput);

            return result;
        }

        // HMAC with SHA-256
        static byte[] applyHMACwithSHA256(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA256 hmacSHA256 = new HMACSHA256(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA256.ComputeHash(byteInput);

            return result;
        }

        // HMAC with SHA-384
        static byte[] applyHMACwithSHA384(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA384 hmacSHA384 = new HMACSHA384(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA384.ComputeHash(byteInput);

            return result;
        }

        // HMAC with SHA-512
        static byte[] applyHMACwithSHA512(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA512 hmacSHA512 = new HMACSHA512(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA512.ComputeHash(byteInput);

            return result;
        }

        /*    SYMMETRIC CIPHERS     */

        // encryption with AES-128
        static byte[] encryptWithAES128(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;

            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        // encryption with AES-192
        static byte[] encryptWithAES192(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-192
            aesObject.KeySize = 192;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;

            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        // encryption with AES-256
        static byte[] encryptWithAES256(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-256
            aesObject.KeySize = 256;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            // RijndaelManaged Mode property doesn't support CFB and OFB modes. 
            //If you want to use one of those modes, you should use RijndaelManaged library instead of RijndaelManaged.
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;

            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        // encryption with 3DES
        /*static byte[] encryptWith3DES(string input, byte[] key, byte[] IV)
        {
            // convert input to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create 3DES object
            TripleDESCryptoServiceProvider TripleDESObject = new TripleDESCryptoServiceProvider();
            // set the key
            TripleDESObject.Key = key;
            // set the IV
            TripleDESObject.IV = IV;
            // set the mode -> CipherMode.*
            TripleDESObject.Mode = CipherMode.CBC;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = TripleDESObject.CreateEncryptor();
            byte[] result = null;

            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        */

        // encryption with AES-128
        static byte[] decryptWithAES128(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            // aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        // decryption with AES-192
        static byte[] decryptWithAES192(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-192
            aesObject.KeySize = 192;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            // aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }


        // decryption with AES-256
        static byte[] decryptWithAES256(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            //aesObject.Padding = PaddingMode.Zeros;
            // since we want to use AES-256
            aesObject.KeySize = 256;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        /*
        // decryption with 3DES
        static byte[] decryptWith3DES(string input, byte[] key, byte[] IV)
        {
            // convert input to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create 3DES object
            TripleDESCryptoServiceProvider TripleDESObject = new TripleDESCryptoServiceProvider();
            // set the key
            TripleDESObject.Key = key;
            // set the IV
            TripleDESObject.IV = IV;
            // set the mode -> CipherMode.*
            TripleDESObject.Mode = CipherMode.CBC;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = TripleDESObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        */

        /*    PUBLIC KEY CRYPTOGRAPHY    */

        // RSA encryption with varying bit length
        static byte[] encryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                //true flag is set to perform direct RSA encryption using OAEP padding
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // RSA decryption with varying bit length
        static byte[] decryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                result = rsaObject.Decrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // signing with RSA
        static byte[] signWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.SignData(byteInput, "SHA512");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // verifying with RSA
        static bool verifyWithRSA(string input, int algoLength, string xmlString, byte[] signature)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            bool result = false;

            try
            {
                result = rsaObject.VerifyData(byteInput, "SHA512", signature);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

    }

    class Client
    {
        public String name;
        public Socket socket;
        public String HMAC_key;
        public String public_key;
    }
}
