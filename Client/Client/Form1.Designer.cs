namespace Client
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.textBox_IP = new System.Windows.Forms.TextBox();
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.textBox_Port = new System.Windows.Forms.TextBox();
            this.button_Connect = new System.Windows.Forms.Button();
            this.IPLabel = new System.Windows.Forms.Label();
            this.PortLabel = new System.Windows.Forms.Label();
            this.textBox_Pass = new System.Windows.Forms.TextBox();
            this.label_Pass = new System.Windows.Forms.Label();
            this.button_Disconect = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.textBox_Username = new System.Windows.Forms.TextBox();
            this.button_SendPass = new System.Windows.Forms.Button();
            this.logs = new System.Windows.Forms.RichTextBox();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.button_PrivateKey = new System.Windows.Forms.Button();
            this.button_serverPubKey = new System.Windows.Forms.Button();
            this.button_select_file = new System.Windows.Forms.Button();
            this.openFileDialog2 = new System.Windows.Forms.OpenFileDialog();
            this.button_storage = new System.Windows.Forms.Button();
            this.FiletextBox = new System.Windows.Forms.TextBox();
            this.Filebutton2 = new System.Windows.Forms.Button();
            this.fileNameLabel = new System.Windows.Forms.Label();
            this.button_grant_permission = new System.Windows.Forms.Button();
            this.button_reject_permission = new System.Windows.Forms.Button();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.SuspendLayout();
            // 
            // textBox_IP
            // 
            this.textBox_IP.Location = new System.Drawing.Point(79, 27);
            this.textBox_IP.Name = "textBox_IP";
            this.textBox_IP.Size = new System.Drawing.Size(100, 20);
            this.textBox_IP.TabIndex = 0;
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(61, 4);
            // 
            // textBox_Port
            // 
            this.textBox_Port.Location = new System.Drawing.Point(79, 53);
            this.textBox_Port.Name = "textBox_Port";
            this.textBox_Port.Size = new System.Drawing.Size(100, 20);
            this.textBox_Port.TabIndex = 2;
            // 
            // button_Connect
            // 
            this.button_Connect.Location = new System.Drawing.Point(79, 104);
            this.button_Connect.Name = "button_Connect";
            this.button_Connect.Size = new System.Drawing.Size(100, 23);
            this.button_Connect.TabIndex = 3;
            this.button_Connect.Text = "Connect";
            this.button_Connect.UseVisualStyleBackColor = true;
            this.button_Connect.Click += new System.EventHandler(this.button_Connect_Click);
            // 
            // IPLabel
            // 
            this.IPLabel.AutoSize = true;
            this.IPLabel.Location = new System.Drawing.Point(56, 30);
            this.IPLabel.Name = "IPLabel";
            this.IPLabel.Size = new System.Drawing.Size(17, 13);
            this.IPLabel.TabIndex = 4;
            this.IPLabel.Text = "IP";
            // 
            // PortLabel
            // 
            this.PortLabel.AutoSize = true;
            this.PortLabel.Location = new System.Drawing.Point(47, 56);
            this.PortLabel.Name = "PortLabel";
            this.PortLabel.Size = new System.Drawing.Size(26, 13);
            this.PortLabel.TabIndex = 5;
            this.PortLabel.Text = "Port";
            // 
            // textBox_Pass
            // 
            this.textBox_Pass.Location = new System.Drawing.Point(79, 274);
            this.textBox_Pass.Name = "textBox_Pass";
            this.textBox_Pass.Size = new System.Drawing.Size(100, 20);
            this.textBox_Pass.TabIndex = 6;
            // 
            // label_Pass
            // 
            this.label_Pass.AutoSize = true;
            this.label_Pass.Location = new System.Drawing.Point(20, 277);
            this.label_Pass.Name = "label_Pass";
            this.label_Pass.Size = new System.Drawing.Size(53, 13);
            this.label_Pass.TabIndex = 7;
            this.label_Pass.Text = "Password";
            // 
            // button_Disconect
            // 
            this.button_Disconect.Enabled = false;
            this.button_Disconect.Location = new System.Drawing.Point(79, 133);
            this.button_Disconect.Name = "button_Disconect";
            this.button_Disconect.Size = new System.Drawing.Size(100, 23);
            this.button_Disconect.TabIndex = 8;
            this.button_Disconect.Text = "Disconnect";
            this.button_Disconect.UseVisualStyleBackColor = true;
            this.button_Disconect.Click += new System.EventHandler(this.button_Disconect_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(18, 82);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(55, 13);
            this.label1.TabIndex = 10;
            this.label1.Text = "Username";
            // 
            // textBox_Username
            // 
            this.textBox_Username.Location = new System.Drawing.Point(79, 79);
            this.textBox_Username.Name = "textBox_Username";
            this.textBox_Username.Size = new System.Drawing.Size(100, 20);
            this.textBox_Username.TabIndex = 9;
            // 
            // button_SendPass
            // 
            this.button_SendPass.Enabled = false;
            this.button_SendPass.Location = new System.Drawing.Point(79, 300);
            this.button_SendPass.Name = "button_SendPass";
            this.button_SendPass.Size = new System.Drawing.Size(100, 23);
            this.button_SendPass.TabIndex = 11;
            this.button_SendPass.Text = "Login";
            this.button_SendPass.UseVisualStyleBackColor = true;
            this.button_SendPass.Click += new System.EventHandler(this.button_SendPass_Click);
            // 
            // logs
            // 
            this.logs.EnableAutoDragDrop = true;
            this.logs.Location = new System.Drawing.Point(459, 26);
            this.logs.Name = "logs";
            this.logs.ReadOnly = true;
            this.logs.Size = new System.Drawing.Size(396, 409);
            this.logs.TabIndex = 12;
            this.logs.Text = "";
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // button_PrivateKey
            // 
            this.button_PrivateKey.Enabled = false;
            this.button_PrivateKey.Location = new System.Drawing.Point(50, 185);
            this.button_PrivateKey.Name = "button_PrivateKey";
            this.button_PrivateKey.Size = new System.Drawing.Size(134, 22);
            this.button_PrivateKey.TabIndex = 13;
            this.button_PrivateKey.Text = "Select Private Key";
            this.button_PrivateKey.UseVisualStyleBackColor = true;
            this.button_PrivateKey.Click += new System.EventHandler(this.button_PrivateKey_Click);
            // 
            // button_serverPubKey
            // 
            this.button_serverPubKey.Enabled = false;
            this.button_serverPubKey.Location = new System.Drawing.Point(50, 213);
            this.button_serverPubKey.Name = "button_serverPubKey";
            this.button_serverPubKey.Size = new System.Drawing.Size(134, 23);
            this.button_serverPubKey.TabIndex = 14;
            this.button_serverPubKey.Text = "Select Server Public Key";
            this.button_serverPubKey.UseVisualStyleBackColor = true;
            this.button_serverPubKey.Click += new System.EventHandler(this.button1_Click);
            // 
            // button_select_file
            // 
            this.button_select_file.Enabled = false;
            this.button_select_file.Location = new System.Drawing.Point(59, 372);
            this.button_select_file.Name = "button_select_file";
            this.button_select_file.Size = new System.Drawing.Size(132, 23);
            this.button_select_file.TabIndex = 15;
            this.button_select_file.Text = "Upload a File";
            this.button_select_file.UseVisualStyleBackColor = true;
            this.button_select_file.Click += new System.EventHandler(this.button_select_file_Click);
            // 
            // openFileDialog2
            // 
            this.openFileDialog2.FileName = "openFileDialog2";
            // 
            // button_storage
            // 
            this.button_storage.Location = new System.Drawing.Point(59, 400);
            this.button_storage.Name = "button_storage";
            this.button_storage.Size = new System.Drawing.Size(132, 23);
            this.button_storage.TabIndex = 16;
            this.button_storage.Text = "Select Storage Folder";
            this.button_storage.UseVisualStyleBackColor = true;
            this.button_storage.Click += new System.EventHandler(this.button_storage_Click);
            // 
            // FiletextBox
            // 
            this.FiletextBox.Location = new System.Drawing.Point(307, 26);
            this.FiletextBox.Name = "FiletextBox";
            this.FiletextBox.Size = new System.Drawing.Size(100, 20);
            this.FiletextBox.TabIndex = 17;
            this.FiletextBox.TextChanged += new System.EventHandler(this.textBox1_TextChanged);
            // 
            // Filebutton2
            // 
            this.Filebutton2.Enabled = false;
            this.Filebutton2.Location = new System.Drawing.Point(307, 51);
            this.Filebutton2.Name = "Filebutton2";
            this.Filebutton2.Size = new System.Drawing.Size(102, 23);
            this.Filebutton2.TabIndex = 18;
            this.Filebutton2.Text = "Request a File";
            this.Filebutton2.UseVisualStyleBackColor = true;
            this.Filebutton2.Click += new System.EventHandler(this.button1_Click_1);
            // 
            // fileNameLabel
            // 
            this.fileNameLabel.AutoSize = true;
            this.fileNameLabel.Location = new System.Drawing.Point(253, 29);
            this.fileNameLabel.Name = "fileNameLabel";
            this.fileNameLabel.Size = new System.Drawing.Size(49, 13);
            this.fileNameLabel.TabIndex = 19;
            this.fileNameLabel.Text = "Filename";
            this.fileNameLabel.Click += new System.EventHandler(this.label2_Click);
            // 
            // button_grant_permission
            // 
            this.button_grant_permission.Enabled = false;
            this.button_grant_permission.Location = new System.Drawing.Point(266, 116);
            this.button_grant_permission.Name = "button_grant_permission";
            this.button_grant_permission.Size = new System.Drawing.Size(141, 40);
            this.button_grant_permission.TabIndex = 20;
            this.button_grant_permission.Text = "Grant Permission";
            this.button_grant_permission.UseVisualStyleBackColor = true;
            this.button_grant_permission.Click += new System.EventHandler(this.button_grant_permission_Click);
            // 
            // button_reject_permission
            // 
            this.button_reject_permission.Enabled = false;
            this.button_reject_permission.Location = new System.Drawing.Point(268, 165);
            this.button_reject_permission.Name = "button_reject_permission";
            this.button_reject_permission.Size = new System.Drawing.Size(141, 40);
            this.button_reject_permission.TabIndex = 21;
            this.button_reject_permission.Text = "Reject Permission";
            this.button_reject_permission.UseVisualStyleBackColor = true;
            this.button_reject_permission.Click += new System.EventHandler(this.button_reject_permission_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(867, 447);
            this.Controls.Add(this.button_reject_permission);
            this.Controls.Add(this.button_grant_permission);
            this.Controls.Add(this.fileNameLabel);
            this.Controls.Add(this.Filebutton2);
            this.Controls.Add(this.FiletextBox);
            this.Controls.Add(this.button_storage);
            this.Controls.Add(this.button_select_file);
            this.Controls.Add(this.button_serverPubKey);
            this.Controls.Add(this.button_PrivateKey);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.button_SendPass);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.textBox_Username);
            this.Controls.Add(this.button_Disconect);
            this.Controls.Add(this.label_Pass);
            this.Controls.Add(this.textBox_Pass);
            this.Controls.Add(this.PortLabel);
            this.Controls.Add(this.IPLabel);
            this.Controls.Add(this.button_Connect);
            this.Controls.Add(this.textBox_Port);
            this.Controls.Add(this.textBox_IP);
            this.Name = "Form1";
            this.Text = "Client";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox textBox_IP;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.TextBox textBox_Port;
        private System.Windows.Forms.Button button_Connect;
        private System.Windows.Forms.Label IPLabel;
        private System.Windows.Forms.Label PortLabel;
        private System.Windows.Forms.TextBox textBox_Pass;
        private System.Windows.Forms.Label label_Pass;
        private System.Windows.Forms.Button button_Disconect;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox textBox_Username;
        private System.Windows.Forms.Button button_SendPass;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Button button_PrivateKey;
        private System.Windows.Forms.Button button_serverPubKey;
        public System.Windows.Forms.RichTextBox logs;
        private System.Windows.Forms.Button button_select_file;
        private System.Windows.Forms.OpenFileDialog openFileDialog2;
        private System.Windows.Forms.Button button_storage;
        private System.Windows.Forms.TextBox FiletextBox;
        private System.Windows.Forms.Button Filebutton2;
        private System.Windows.Forms.Label fileNameLabel;
        private System.Windows.Forms.Button button_grant_permission;
        private System.Windows.Forms.Button button_reject_permission;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog1;
    }
}

