
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;



namespace Client
{


    public partial class Form1 : Form
    {
        bool terminating = false;
        bool connected = false;
        Socket clientSocket;


        String selectedPrivateKeyPath;
        String encryptedPrivateKey;

        String decryptedPrivateKey;

        String serverPublicKey;

        String decryptedHMAC; //added after demo

        String password;

        String requesting_publickey;
        
        //String client_storage_path = "C:\\Users\\Efehan\\Desktop\\CS 432 Project\\cs432Project\\Client\\Client\\Project-keys\\Client Storage\\";
        String client_storage_path;

        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }



        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            connected = false;
            terminating = true;
            Environment.Exit(0);
        }

        //this is the functionality of "Connect" button: IP, Port, username should be entered
        private void button_Connect_Click(object sender, EventArgs e)
        {

            clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            string IP = textBox_IP.Text;
            int port;

            if (Int32.TryParse(textBox_Port.Text, out port))
            {
                try
                {
                    if (port > 65536)
                    {
                        logs.AppendText("Invalid port number.\n");
                        return;
                    }
                    //connect to server
                    clientSocket.Connect(IP, port); // IP:port --> socket,  127.0.0.1:8080
                    button_Connect.Enabled = false;
                    connected = true;
                    //logs.AppendText("Connected to the server.\n");

                    // send username
                    String message = textBox_Username.Text;
                    if (message != "" && message.Length < 63)
                    {
                        Byte[] buffer = new Byte[64];
                        buffer = Encoding.Default.GetBytes(message);
                        clientSocket.Send(buffer);
                    }
                    else
                        return;

                    //TODO: recieve feedback from server (related to username)
                    Byte[] bufferX = new Byte[64]; // word\0\0\0\0...... until we have the size 64
                    clientSocket.Receive(bufferX);
                    string incomingMessage = Encoding.Default.GetString(bufferX);
                    incomingMessage = incomingMessage.Substring(0, incomingMessage.IndexOf('\0'));
                    logs.AppendText("Server: " + incomingMessage + "\n");
                    if (incomingMessage.Contains("Error"))
                    {
                        Disconnect();
                        return;
                    }

                    button_Disconect.Enabled = true;
                    button_PrivateKey.Enabled = true;
                    button_SendPass.Enabled = true;
                    button_serverPubKey.Enabled = true;
                }
                catch
                {
                    logs.AppendText("Could not connect to the server.\n");
                    initClient();
                }

            }
            else
            {
                logs.AppendText("Check the port number.\n");
                Disconnect();

            }
        }

        //TODO: exception handling in all crypto operations
        //this is called when a user is connected
        private void Receive()
        {
            try
            {

                //TODO: recieve random number from server
                Byte[] nonce_128 = new Byte[16]; // word\0\0\0\0...... until we have the size 64
                clientSocket.Receive(nonce_128);
                string incomingMessage = Encoding.Default.GetString(nonce_128);
                logs.AppendText("Server sent this nonce: " + generateHexStringFromByteArray(nonce_128) + "\n");

                //sign the random number with decrypted private key
                byte[] amazonBytes = signWithRSA(incomingMessage, 4096, decryptedPrivateKey);
                //send the signed nonce back to server
                clientSocket.Send(amazonBytes);
                logs.AppendText("Signing this:" + generateHexStringFromByteArray(nonce_128) + "\nAnd sent as " + generateHexStringFromByteArray(amazonBytes) + "\n");


                Byte[] server_merged_message = new Byte[1028];
                clientSocket.Receive(server_merged_message);
                logs.AppendText("\nA message has been recieved from server:\n");
                //seperate the merged message
                byte[] signedHMAC_ack = new byte[512];
                byte[] ack_message = new byte[4];
                byte[] enc_HMAC = new byte[512];
                Array.Copy(server_merged_message, 0, signedHMAC_ack, 0, 512);
                logs.AppendText("\nFirst part is : " + generateHexStringFromByteArray(signedHMAC_ack) + "\n");

                Array.Copy(server_merged_message, 512, ack_message, 0, 4);
                logs.AppendText("\nSecond part is : " + generateHexStringFromByteArray(ack_message) + "\n");
                String mess_ack_message = Encoding.Default.GetString(ack_message); // ack positive/negative

                Array.Copy(server_merged_message, 516, enc_HMAC, 0, 512);
                logs.AppendText("\nThird part is : " + generateHexStringFromByteArray(enc_HMAC) + "\n");
                String mess_enc_HMAC = Encoding.Default.GetString(enc_HMAC);

                //verify sign of server
                bool verificationResult = verifyWithRSA(mess_enc_HMAC + mess_ack_message, 4096, serverPublicKey, signedHMAC_ack);

                // UPDATED after Demo
                if (verificationResult == true)
                {
                    if (mess_ack_message.Equals("Ack1"))
                    {
                        logs.AppendText("Positive Acknowledgement\n");
                        logs.AppendText("You are authenticated by the server.\n");
                        //Decrypt HMAC
                        byte[] decryptedHMAC_ = decryptWithRSA(mess_enc_HMAC, 4096, decryptedPrivateKey);
                        decryptedHMAC = generateHexStringFromByteArray(decryptedHMAC_);
                        logs.AppendText("Decrypted HMAC from server : " + decryptedHMAC + "\n");
                        //button_select_file.Enabled = true;
                        //Filebutton2.Enabled = true;
                        button_storage.Enabled = true;
                    }
                    else
                    {
                        logs.AppendText("Negative Acknowledgement\n");
                        logs.AppendText("You are NOT authenticated by the server.\n");
                        logs.AppendText("Warning!! Authentication failed!!.Closing the Connection.\n");
                        Disconnect();
                        return;
                    }
                }
                else
                {
                    logs.AppendText("Error!! couldn't verify server's signature\n");
                    logs.AppendText("Warning!! Authentication failed!!.Closing the Connection.\n");
                    Disconnect();
                    return;
                }

                while (connected)
                {
                    try
                    {
                        logs.AppendText("\n====Now listening!!!!====");
                        Byte[] buffer = new Byte[65000];
                        clientSocket.Receive(buffer);
                        Byte[] mesClass = new Byte[8];
                        Array.Copy(buffer, 0, mesClass, 0, 8);  //get the message type
                        String mClass = Encoding.Default.GetString(mesClass);
                        logs.AppendText($"\nReceived status: {mClass} from server.\n");
                        if (mClass.Equals("UPL_ACK1") || mClass.Equals("UPL_ACK0"))   //Upload messages!!!
                        {
                            
                            incomingMessage = Encoding.Default.GetString(buffer);
                            int star = incomingMessage.IndexOf('*');
                            byte[] enc_message = new byte[512];
                            byte[] ack_message_x = new byte[128];
                            Array.Copy(buffer, 0, ack_message_x, 0, star); //check this
                            Array.Copy(buffer, star + 1, enc_message, 0, 512);



                            //incomingMessage = incomingMessage.Substring(0, incomingMessage.IndexOf('\0'));

                            String acknowledgment = Encoding.Default.GetString(ack_message_x).Substring(0, 8);

                            logs.AppendText($"\nAcknowledgement message {acknowledgment}\n");
                            logs.AppendText($"\nEncrypted message: {generateHexStringFromByteArray(enc_message)}\n");

                            String ack_filename_string = Encoding.Default.GetString(ack_message_x).Substring(0, Encoding.Default.GetString(ack_message_x).IndexOf('\0'));
                            //bool verificationAckResult = verifyWithRSA(incomingMessage.Substring(0, incomingMessage.IndexOf('*')+1), 4096, serverPublicKey, Encoding.Default.GetBytes(incomingMessage.Substring(incomingMessage.IndexOf('*')+1)));
                            bool verificationAckResult = verifyWithRSA(ack_filename_string, 4096, serverPublicKey, enc_message);

                            if (verificationAckResult)
                            {
                                logs.AppendText("Server was verified with signature.\n");
                            }
                            else
                            {
                                logs.AppendText("Couldnt verify the signature of the server.\n");
                            }
                            if (acknowledgment.Equals("UPL_ACK1"))
                            {
                                
                                KeysFileName.new_name = ack_filename_string.Substring(8);
                                String keysfiletext = Encoding.Default.GetString(KeysFileName.keys) + KeysFileName.new_name + "*" + KeysFileName.original_name;            //remember!! empty chars may be problem here

                                //encrypt the file first
                                byte[] enc_keysfiletext = encryptWithRSA(keysfiletext,4096,decryptedPrivateKey);
                                byte[] aes_key_256 = new byte[32];
                                byte[] aes_iv_128 = new byte[16];
                                Array.Copy(KeysFileName.keys, 0, aes_key_256, 0, 32); //key: [0...31]
                                Array.Copy(KeysFileName.keys, 32, aes_iv_128, 0, 16); // iv: key: [32...47]
                                logs.AppendText($"\nKey: {generateHexStringFromByteArray(aes_key_256)} and IV: {generateHexStringFromByteArray(aes_iv_128)} will be encrypted with private key and will be saved to a file.\n");
                                logs.AppendText($"\nEncrypted version of key+iv: {generateHexStringFromByteArray(enc_keysfiletext)}\n");
                                logs.AppendText("Server sent positive acknowledgment. File is saved as: " + ack_filename_string.Substring(8) + "\n");
                                File.WriteAllBytes(client_storage_path + ack_filename_string.Substring(8) + "_keysNames", enc_keysfiletext);  //client storage harcoded for now   //writing the keys and filenames
                                

                            }
                            else
                            {
                                logs.AppendText("Server sent negative acknowledgment. File has NOT been saved.\n");

                            }
                        }
                        
                        //download messages

                        else if (mClass.Equals("FDN_Ack0")) //file denied because of client's signature
                        {
                            byte[] signed_message = new byte[512];
                            Array.Copy(buffer, mClass.Length, signed_message, 0, 512);
                            logs.AppendText($"\nSigned_message: {generateHexStringFromByteArray(signed_message)}\n");
                            bool verificationAckResult = verifyWithRSA(mClass, 4096, serverPublicKey, signed_message);
                            if (verificationAckResult)
                            {
                                logs.AppendText("\nFile is denied, your signature could't be verified by the server\n");
                            }
                            else
                            {
                                logs.AppendText("\nFile is denied, Also couldn't verify server's signature.\n");
                            }
                        }

                        else if (mClass.Equals("FNA_Ack0")) //file denied because of file does not exist in the server storage
                        {
                            byte[] signed_message = new byte[512];
                            Array.Copy(buffer, mClass.Length, signed_message, 0, 512);
                            logs.AppendText($"\nSigned message: {generateHexStringFromByteArray(signed_message)}\n");
                            bool verificationAckResult = verifyWithRSA(mClass, 4096, serverPublicKey, signed_message);
                            if (verificationAckResult)
                            {
                                logs.AppendText("\nSignature of Server is verified and File does not exist in the server!!!\n");
                            }
                            else
                            {
                                logs.AppendText("\nFile does not exists, Also couldn't verify server's signature.\n");
                            }
                        }
                        else if (mClass.Equals("ONA_Ack0")) //file denied because owner is not connected
                        {
                            byte[] signed_message = new byte[512];
                            Array.Copy(buffer, mClass.Length, signed_message, 0, 512);
                            logs.AppendText($"\nSigned_message: {generateHexStringFromByteArray(signed_message)}\n");
                            bool verificationAckResult = verifyWithRSA(mClass, 4096, serverPublicKey, signed_message);
                            if (verificationAckResult)
                            {
                                logs.AppendText("\nOwner of the file isn't connected to server!!!\n");
                            }
                            else
                            {
                                logs.AppendText("\nOwner of the file isn't connected to server, Also couldn't verify server's signature.\n");
                            }
                        }

                        else if (mClass.Equals("OFil_Ack")) //owner is requesting the file
                        {
                            incomingMessage = Encoding.Default.GetString(buffer);
                            incomingMessage = incomingMessage.Substring(mClass.Length, incomingMessage.IndexOf('\0'));
                            int fileLen = Int32.Parse(incomingMessage);
                            logs.AppendText($"\nFile length: {fileLen}\n");

                            byte[] buffer2 = new byte[65000];
                            clientSocket.Receive(buffer2); //recieve main message
                            byte[] signed_enc_file = new byte[512];
                            byte[] enc_file = new byte[fileLen];
                            Array.Copy(buffer2, mClass.Length, signed_enc_file, 0, signed_enc_file.Length);
                            Array.Copy(buffer2, mClass.Length + signed_enc_file.Length, enc_file, 0, enc_file.Length);
                            logs.AppendText($"\nReceived signed encoded file {generateHexStringFromByteArray(signed_enc_file)}\n");
                            bool verificationAckResult = verifyWithRSA(Encoding.Default.GetString(enc_file), 4096, serverPublicKey, signed_enc_file);
                            //logs.AppendText($"\nEncrypted file is: {generateHexStringFromByteArray(enc_file)}\n");

                            if (verificationAckResult)
                            {
                                logs.AppendText("\nServer's signature is verified.\n");

                                byte[] enc_keysFile = File.ReadAllBytes(client_storage_path + ToDownload.filename + "_keysNames"); //get the key file and decrypt it
                                byte[] keysFile = decryptWithRSA(Encoding.Default.GetString(enc_keysFile), 4096, decryptedPrivateKey);
                                byte[] keys = new byte[48];
                                byte[] filenames = new byte[keysFile.Length - keys.Length];  
                                Array.Copy(keysFile, 0, keys, 0, keys.Length);
                                Array.Copy(keysFile, keys.Length, filenames, 0, filenames.Length);

                                String fnames = Encoding.Default.GetString(filenames);
                                String original = fnames.Split('*')[1];
                                

                                byte[] aes_key_256 = new byte[32];
                                byte[] aes_iv_128 = new byte[16];
                                Array.Copy(keys, 0, aes_key_256, 0, 32); //key: [0...31]
                                Array.Copy(keys, 32, aes_iv_128, 0, 16); // iv: key: [32...47]
                                logs.AppendText($"\nReceived encrypted file will be decrypted usind AES KEY:{generateHexStringFromByteArray(aes_key_256)} IV:{generateHexStringFromByteArray(aes_iv_128)}\n");
                                //keys are collected now to decrypt and write the file again in the client storage
                                byte[] decryptedAES256CBC_file = decryptWithAES256CBC(Encoding.Default.GetString(enc_file), aes_key_256, aes_iv_128);  //decrypt the file
                                File.WriteAllBytes(client_storage_path + original, decryptedAES256CBC_file);  //client storage harcoded for now


                                logs.AppendText("\nFile is saved to the client storage successfully.Original name: " + original +"\n");



                            }
                            else
                            {
                                logs.AppendText("File request is granted but couldn't verify server's signature.\n");
                            }

                        }
                        else if (mClass.Equals("RLY_ACK1")) //relay to owner of the file
                        {
                            byte[] hamc_merged = new byte[64];
                            Array.Copy(buffer, mClass.Length, hamc_merged, 0, hamc_merged.Length);

                            byte[] merged_mess = new byte[40000];
                            Array.Copy(buffer, hamc_merged.Length + mClass.Length, merged_mess, 0, merged_mess.Length);
                            String mergedmess = Encoding.Default.GetString(merged_mess);
                            mergedmess = mergedmess.Substring(0, mergedmess.IndexOf('\0'));
                            //logs.AppendText($"\nRLY_ACK1 message: {mergedmess}\n");


                            byte[] check_hamc_merged = applyHMACwithSHA512(mergedmess, hexStringToByteArray(decryptedHMAC));
                            logs.AppendText($"\nServer sent this HMAC: {generateHexStringFromByteArray(hamc_merged)}\n");
                            logs.AppendText($"\nServer sent this plaintext: {mergedmess}\n");
                            logs.AppendText($"\nHMAC of this plaintext is: {generateHexStringFromByteArray(check_hamc_merged)}\n");


                            if (Encoding.Default.GetString(check_hamc_merged).Equals(Encoding.Default.GetString(hamc_merged)))
                            {
                                logs.AppendText($"\nHMAC is verified\n");

                                String fileName = mergedmess.Substring(0, mergedmess.IndexOf('*'));
                                if (!File.Exists(client_storage_path + fileName + "_keysNames"))
                                {
                                    logs.AppendText("\nCouldnt find the key files at: " + client_storage_path + fileName + "_keysNames");
                                    continue;
                                }
                                byte[] enc_keysFile = File.ReadAllBytes(client_storage_path + fileName + "_keysNames");  //get the key file and decrypt it

                                logs.AppendText($"\nDecrypting {fileName} using {decryptedPrivateKey}\n");
                                byte[] keysFile = decryptWithRSA(Encoding.Default.GetString(enc_keysFile), 4096, decryptedPrivateKey);

                                byte[] keys = new byte[48];
                                byte[] filenames = new byte[keysFile.Length - keys.Length];  //filename length can be max 500 chars
                                Array.Copy(keysFile, 0, keys, 0, keys.Length);
                                Array.Copy(keysFile, keys.Length, filenames, 0, filenames.Length);

                                byte[] aes_key_256 = new byte[32];
                                byte[] aes_iv_128 = new byte[16];
                                Array.Copy(keys, 0, aes_key_256, 0, 32); //key: [0...31]
                                Array.Copy(keys, 32, aes_iv_128, 0, 16); // iv: key: [32...47]

                                logs.AppendText($"\nDecryption result: KEY:{generateHexStringFromByteArray(aes_key_256)} and IV: {generateHexStringFromByteArray(aes_iv_128)}\n");


                                String fnames = Encoding.Default.GetString(filenames);
                                String original = fnames.Split('*')[1];

                                KeysFileName.keys = keys;
                                KeysFileName.original_name = original;
                                KeysFileName.new_name = fileName;

                                requesting_publickey = mergedmess.Substring(mergedmess.IndexOf('!') + 1);

                                logs.AppendText("\n"+ mergedmess.Substring(mergedmess.IndexOf('*')+1, mergedmess.IndexOf('!') - mergedmess.IndexOf('*') -1) +" asked for your permission and HMAC verified for file: " + fileName);
                                logs.AppendText("\nWaiting for your Approval/Rejection");

                                button_grant_permission.Enabled = true;
                                button_reject_permission.Enabled = true;
                            }
                            else
                            {
                                logs.AppendText("\nServer asked for your permission and HMAC NOT verified, sending a signed negative message to server to stop protocol");

                                String error_mes = "2";
                                byte[] error_mes_byte = Encoding.Default.GetBytes(error_mes);
                                byte[] sign_err = signWithRSA(error_mes, 4096, decryptedPrivateKey);
                                
                                byte[] merged_mes_Err = new byte[sign_err.Length + error_mes_byte.Length];
                                Array.Copy(error_mes_byte, 0, merged_mes_Err, 0, error_mes_byte.Length);
                                Array.Copy(sign_err, 0, merged_mes_Err, error_mes_byte.Length, sign_err.Length);

                                clientSocket.Send(merged_mes_Err);
                                logs.AppendText($"\nSent server message (error + signed rsa): {generateHexStringFromByteArray(merged_mes_Err)}\n");

                            }
                        }

                        else if (mClass.Equals("FIN_Ack1"))  //final message relayed to the requester
                        {
                            incomingMessage = Encoding.Default.GetString(buffer);
                            incomingMessage = incomingMessage.Substring(mClass.Length, incomingMessage.IndexOf('\0'));
                            String[] sizes = incomingMessage.Split('|');
                            int encKeyLen = Int32.Parse(sizes[0]);
                            int fileLen = Int32.Parse(sizes[1]);

                            byte[] buffer2 = new byte[65000];
                            clientSocket.Receive(buffer2); //recieve main message
                            byte[] signed_message = new byte[512];
                            byte[] enc_file = new byte[fileLen];
                            byte[] enc_keys = new byte[encKeyLen];

                            Array.Copy(buffer2, mClass.Length, signed_message, 0, signed_message.Length);
                            Array.Copy(buffer2, mClass.Length + signed_message.Length, enc_keys, 0, enc_keys.Length);
                            Array.Copy(buffer2, mClass.Length + signed_message.Length + enc_keys.Length, enc_file, 0, enc_file.Length);

                            logs.AppendText($"\nEncrypted keys: {generateHexStringFromByteArray(enc_keys)}, \nEncrypted file:(not shown here becasue of UI complexity), \nsigned message: {generateHexStringFromByteArray(signed_message)}\n");
                            bool verificationAckResult = verifyWithRSA(Encoding.Default.GetString(enc_keys) + Encoding.Default.GetString(enc_file), 4096, serverPublicKey, signed_message);

                            if (verificationAckResult)
                            {
                                logs.AppendText("\nServer's signature is verified\n");
                                logs.AppendText("\nPermission is given by the owner\n");

                                byte[] dec_keys = decryptWithRSA(Encoding.Default.GetString(enc_keys), 4096, decryptedPrivateKey);

                                byte[] aes_key_256 = new byte[32];
                                byte[] aes_iv_128 = new byte[16];
                                byte[] original_fname = new byte[dec_keys.Length - aes_key_256.Length - aes_iv_128.Length];

                                Array.Copy(dec_keys, 0, aes_key_256, 0, aes_key_256.Length);
                                Array.Copy(dec_keys, aes_key_256.Length, aes_iv_128, 0, aes_iv_128.Length);
                                Array.Copy(dec_keys, aes_key_256.Length + aes_iv_128.Length, original_fname, 0, original_fname.Length);

                                //keys are collected now to decrypt and write the file again in the client storage

                                String original = Encoding.Default.GetString(original_fname);
                                //original = original.Substring(0, original.IndexOf('\0'));

                                byte[] decryptedAES256CBC_file = decryptWithAES256CBC(Encoding.Default.GetString(enc_file), aes_key_256, aes_iv_128);  //decrypt the file
                                logs.AppendText($"\nReceived encrypted file will be decrypted usind AES KEY:{generateHexStringFromByteArray(aes_key_256)} IV:{generateHexStringFromByteArray(aes_iv_128)}\n");

                                //logs.AppendText($"\nDecrypted file: {generateHexStringFromByteArray(decryptedAES256CBC_file)}\n");
                                File.WriteAllBytes(client_storage_path + original, decryptedAES256CBC_file);  //client storage harcoded for now

                                logs.AppendText("\nFile is saved to the client storage successfully. With original name: " + original + "\n");

                            }
                            else
                            {
                                logs.AppendText("\nServer's signature is NOT verified in final phase!!\n");
                            }


                        }

                        else if (mClass.Equals("FIN_Ack0"))
                        {
                            String signed_neg_message = (Encoding.Default.GetString(buffer)).Substring(mClass.Length,512);
                            logs.AppendText($"\nSigned message: {generateHexStringFromByteArray(Encoding.Default.GetBytes(signed_neg_message))}\n");

                            bool verificationAckResult = verifyWithRSA(mClass, 4096, serverPublicKey,Encoding.Default.GetBytes(signed_neg_message));
                            if (verificationAckResult)
                            {
                                logs.AppendText("\nServer's signature is verified\n");
                                logs.AppendText("\nPermission is not granted from the owner, file is not delivered!!\n");
                            }
                            else
                            {
                                logs.AppendText("\nServer's signature is NOT verified in final phase!!\n");
                            }
                        }

                    }
                    catch
                    {

                        if (!terminating)
                        {
                            logs.AppendText("\nThe server has disconnected.\n");
                        }
                        Disconnect();
                        connected = false;

                    }
                }

            }
            catch (Exception e)
            {
                logs.AppendText("The connection with the server was closed!\n");
                Disconnect();

            }

        }


        //this will send password
        private void button_SendPass_Click(object sender, EventArgs e)
        {
            if (serverPublicKey == null)
            {
                logs.AppendText("\nPlease select public key of server");
                return;
            }
            try
            {

                //decrypt private key with the hash of password
                // hash using SHA-384
                password = textBox_Pass.Text;
                byte[] password_sha384 = hashWithSHA384(password); //convert password to bytes

                // decryption with AES-256
                byte[] AES_enc_key = new byte[32];
                Array.Copy(password_sha384, 0, AES_enc_key, 0, 32); //key: [0...31]
                byte[] AES_iv = new byte[16];
                Array.Copy(password_sha384, 32, AES_iv, 0, 16); // iv: key: [32...47]

                byte[] decryptedAES256;
                try
                {
                    decryptedAES256 = decryptWithAES256(encryptedPrivateKey, AES_enc_key, AES_iv);
                    if (decryptedAES256.Equals(null))
                        throw new Exception();
                }
                catch (Exception)
                {
                    logs.AppendText("Password is incorrect. Please enter again. Otherwise private key may be incorrect.\n");
                    //user enters his password again

                    return;
                }

                logs.AppendText($"\nClient AES key: {generateHexStringFromByteArray(AES_enc_key)}\n");
                logs.AppendText($"\nClient IV key: {generateHexStringFromByteArray(AES_iv)}\n");

                String encryptedAES256 = Encoding.Default.GetString(encryptWithAES256(Encoding.Default.GetString(decryptedAES256), AES_enc_key, AES_iv));

                decryptedPrivateKey = Encoding.Default.GetString(decryptedAES256);


                Thread receiveThread = new Thread(Receive);
                receiveThread.Start();
            }
            catch
            {
                logs.AppendText("Could not contact server.\n");
                Disconnect();
            }
        }

        //select client's private key
        private void button_PrivateKey_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog
            {
                InitialDirectory = @"D:\",
                Title = "Select a Key File",

                CheckFileExists = true,
                CheckPathExists = true,

                DefaultExt = "txt",
            };

            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                logs.Text += "Selected file name: " + openFileDialog1.SafeFileName + "\n";
                selectedPrivateKeyPath = openFileDialog1.FileName;
                // using (System.IO.StreamReader fileReader =
                //     new System.IO.StreamReader(selectedPrivateKeyPath))
                //     {
                //         encryptedPrivateKey = fileReader.ReadToEnd();
                //     }
                //using (System.IO.StreamReader fileReader = new System.IO.StreamReader(selectedPrivateKeyPath))
                //{
                //    encryptedPrivateKey = Encoding.Default.GetString(Encoding.Default.GetBytes(fileReader.ReadToEnd()));
                //    //AES128IV = Encoding.Default.GetBytes(fileReader.ReadLine());
                //}
                encryptedPrivateKey = System.IO.File.ReadAllText(selectedPrivateKeyPath);
                encryptedPrivateKey = Encoding.Default.GetString(hexStringToByteArray(encryptedPrivateKey));
            }
            button_serverPubKey.Enabled = true;
        }


        //select server's public key
        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog
            {
                InitialDirectory = @"D:\",
                Title = "Select a Key File",

                CheckFileExists = true,
                CheckPathExists = true,

                DefaultExt = "txt",
            };

            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                logs.Text += "\nSelected file name: " + openFileDialog1.SafeFileName + "\n";

                using (System.IO.StreamReader fileReader = new System.IO.StreamReader(openFileDialog1.FileName))
                {
                    serverPublicKey = Encoding.Default.GetString(Encoding.Default.GetBytes(fileReader.ReadToEnd()));
                }
            }
            button_SendPass.Enabled = true;
        }

        private void button_select_file_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog2 = new OpenFileDialog
            {
                InitialDirectory = @"D:\",
                Title = "Select a File to Send",

                CheckFileExists = true,
                CheckPathExists = true,
            };
            if (openFileDialog2.ShowDialog() == DialogResult.OK)
            {
                logs.Text += "\nThis file will be sent: " + openFileDialog2.SafeFileName + "\n";
            }
            byte[] fileContentBytes;
            //get the content of file in bytes
            using (System.IO.StreamReader fileReader = new System.IO.StreamReader(openFileDialog2.FileName))
            {
                fileContentBytes = Encoding.Default.GetBytes(fileReader.ReadToEnd());
            }

            //produce 256 bit AES key
            byte[] aes_key_256 = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(aes_key_256);
            }
            //produce 128 bit AES IV
            byte[] aes_iv_128 = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(aes_iv_128);
            }

            //save keys for disconnection
            byte[] keys = new byte[48];
            Array.Copy(aes_key_256, 0, keys, 0, 32); //key: [0...31]
            Array.Copy(aes_iv_128, 0, keys, 32, 16); // iv: key: [32...47]

            KeysFileName.keys = keys;
            KeysFileName.original_name = openFileDialog2.SafeFileName;

            logs.AppendText($"Encrypting file content with: KEY: {generateHexStringFromByteArray(aes_key_256)}  and IV:  {generateHexStringFromByteArray(aes_iv_128)} ");

            //encrypt file content with AES 256 CBC
            byte[] encryptedAES256CBC_file = encryptWithAES256CBC(Encoding.Default.GetString(fileContentBytes), aes_key_256, aes_iv_128);
            //encrypt the encrypted file with hmac
            byte[] HMAC_encryptedAES256CBC_file = applyHMACwithSHA512(Encoding.Default.GetString(encryptedAES256CBC_file), hexStringToByteArray(decryptedHMAC));


            byte[] merged_message = new byte[HMAC_encryptedAES256CBC_file.Length + encryptedAES256CBC_file.Length];

            Array.Copy(HMAC_encryptedAES256CBC_file, 0, merged_message, 0, 64);
            Array.Copy(encryptedAES256CBC_file, 0, merged_message, 64, encryptedAES256CBC_file.Length);

            //first send the length of merged message with upload byte
            int lengthOfMergedMessage = merged_message.Length;

            byte[] lenMergedMes = Encoding.Default.GetBytes(lengthOfMergedMessage.ToString());
            byte[] merged_message2 = new byte[1 + lenMergedMes.Length];

            Array.Copy(Encoding.Default.GetBytes("1"), 0, merged_message2, 0, 1);
            Array.Copy(lenMergedMes, 0, merged_message2, 1, lenMergedMes.Length);
            clientSocket.Send(merged_message2);


            // TODO: what will happen if merged_message.length > 65000
            if (merged_message.Length < 65000)
            {
                clientSocket.Send(merged_message);
                logs.AppendText("\nFile size is:" + lengthOfMergedMessage + "\n");
                logs.AppendText("\nHMAC of encrypted file is:" + generateHexStringFromByteArray(HMAC_encryptedAES256CBC_file) + "\n");
                logs.AppendText("\nHMAC and the encrypted file is sent to server");
            }
            //else
            //{
            //    int index = 0;
            //    while (true)
            //    {
            //        index += 65000;
            //    }
            //}
        }

        private void button_storage_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog folderDlg = new FolderBrowserDialog();
            folderDlg.ShowNewFolderButton = true;
            // Show the FolderBrowserDialog.  
            DialogResult result = folderDlg.ShowDialog();
            if (result == DialogResult.OK)
            {
                client_storage_path = folderDlg.SelectedPath + "\\";
            }
            logs.AppendText("\nStorage folder is selected as: " + client_storage_path);
            button_select_file.Enabled = true;
            Filebutton2.Enabled = true;
        }

        private void button1_Click_1(object sender, EventArgs e)  //request/download file
        {
            string filename = FiletextBox.Text;
            ToDownload.filename = filename;
            byte[] signedFileName = signWithRSA(filename, 4096, decryptedPrivateKey);  //sign the filename
            byte[] fname = Encoding.Default.GetBytes(filename);
            
            byte[] merged_message = new byte[1 + 512 + filename.Length];
            Array.Copy(Encoding.Default.GetBytes("0"), 0, merged_message, 0, 1);
            Array.Copy(signedFileName, 0, merged_message, 1, 512);
            Array.Copy(fname, 0, merged_message, 513, filename.Length);
            clientSocket.Send(merged_message);
            logs.AppendText($"\nFilename requested: {filename}");
            logs.AppendText($"\nFilename requested signed: {generateHexStringFromByteArray(signedFileName)}");
            logs.AppendText($"\nFilename and signed filename is sent to server.");
        }

        private void button_grant_permission_Click(object sender, EventArgs e) //if granted permission keys and original file name sent to the server
        {

            byte[] aes_key_256 = new byte[32];
            byte[] aes_iv_128 = new byte[16];
            Array.Copy(KeysFileName.keys, 0, aes_key_256, 0, 32); //key: [0...31]
            Array.Copy(KeysFileName.keys, 32, aes_iv_128, 0, 16); // iv: key: [32...47]
            

            String aes_key_256_Str = Encoding.Default.GetString(aes_key_256);
            String aes_iv_128_Str = Encoding.Default.GetString(aes_iv_128);
            String aes_key_iv_originalFileName = aes_key_256_Str + aes_iv_128_Str + KeysFileName.original_name;

            logs.AppendText($"\nThese will be encrypted with RSA: KEY: {generateHexStringFromByteArray(aes_key_256)} IV: {generateHexStringFromByteArray(aes_iv_128)} , and {KeysFileName.original_name}");

            byte[] enc_rsa = encryptWithRSA(aes_key_iv_originalFileName, 4096, requesting_publickey);

            logs.AppendText($"\nEncryption result: {generateHexStringFromByteArray(enc_rsa)}");


            String pos_permis_ack = "3";
            byte[] pos_permis_Ack_byte = Encoding.Default.GetBytes(pos_permis_ack);

            byte[] hmac_merge = applyHMACwithSHA512(pos_permis_ack + Encoding.Default.GetString(enc_rsa), hexStringToByteArray(decryptedHMAC));
            logs.AppendText($"\nHMAC of positive ack + RSA encryption + session key: {generateHexStringFromByteArray(hmac_merge)}");


            byte[] merge_all = new byte[pos_permis_Ack_byte.Length + hmac_merge.Length + enc_rsa.Length];
            Array.Copy(pos_permis_Ack_byte, 0, merge_all, 0, pos_permis_Ack_byte.Length);
            Array.Copy(hmac_merge, 0, merge_all, pos_permis_Ack_byte.Length, hmac_merge.Length);
            Array.Copy(enc_rsa, 0, merge_all, pos_permis_Ack_byte.Length + hmac_merge.Length, enc_rsa.Length);

            String enc_length = pos_permis_ack + enc_rsa.Length.ToString();
            clientSocket.Send(Encoding.Default.GetBytes(enc_length));

            clientSocket.Send(merge_all);

            logs.AppendText("\nPermission granted for the file, Informed the server by sending psoitive ACK + HMAC + RSA encryption.\n");

            button_grant_permission.Enabled = false;
            button_reject_permission.Enabled = false;
        }

        private void button_reject_permission_Click(object sender, EventArgs e)  //if rejected permission, negative message sent to the server
        {
            String pos_permis_ack = "4";
            byte[] pos_permis_Ack_byte = Encoding.Default.GetBytes(pos_permis_ack);

            byte[] hmac_ack = applyHMACwithSHA512(pos_permis_ack, hexStringToByteArray(decryptedHMAC));

            byte[] merge_mess = new byte[pos_permis_Ack_byte.Length + hmac_ack.Length];
            Array.Copy(pos_permis_Ack_byte, 0, merge_mess, 0, pos_permis_Ack_byte.Length);
            Array.Copy(hmac_ack, 0, merge_mess, pos_permis_Ack_byte.Length, hmac_ack.Length);


            clientSocket.Send(merge_mess);
            logs.AppendText($"\nPermission rejected for the file, Informed the server by sending negative ACK and it's HMAC: {generateHexStringFromByteArray(hmac_ack)}\n");

            button_grant_permission.Enabled = false;
            button_reject_permission.Enabled = false;
        }




        private void button_Disconect_Click(object sender, EventArgs e)
        {
            logs.AppendText("\n Disconnected \n");
            Disconnect();
        }

        public void Disconnect()
        {
            connected = false;
            terminating = true;
            //clientSocket.Shutdown(SocketShutdown.Both);
            clientSocket.Close();
            initClient();
        }

        private void initClient()
        {
            encryptedPrivateKey = "";
            decryptedPrivateKey = "";
            button_PrivateKey.Enabled = false;
            button_serverPubKey.Enabled = false;
            button_Connect.Enabled = true;
            button_Disconect.Enabled = false;
            button_SendPass.Enabled = false;
            button_select_file.Enabled = false;
            Filebutton2.Enabled = false;
            button_grant_permission.Enabled = false;
            button_reject_permission.Enabled = false;

            connected = false;
        }





        // helper functions
        //generates hex string for the keys
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

        // encryption with AES-256 CBC!!!!
        static byte[] encryptWithAES256CBC(string input, byte[] key, byte[] IV)
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
            aesObject.Mode = CipherMode.CBC;
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

        // decryption with AES-256 CBC!!
        static byte[] decryptWithAES256CBC(string input, byte[] key, byte[] IV)
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
            aesObject.Mode = CipherMode.CBC;
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



        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void label2_Click(object sender, EventArgs e)
        {

        }


    }

    public static class KeysFileName
    {
        public static byte[] keys;
        public static string original_name;
        public static string new_name;
    }

    public static class ToDownload
    {
        public static string filename;
    }
}