namespace Server
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
            this.logs = new System.Windows.Forms.RichTextBox();
            this.textBox_Port = new System.Windows.Forms.TextBox();
            this.labelPort = new System.Windows.Forms.Label();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.button_Listen = new System.Windows.Forms.Button();
            this.button_browse = new System.Windows.Forms.Button();
            this.clientBox = new System.Windows.Forms.ListBox();
            this.button_storage = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(243, 12);
            this.logs.Name = "logs";
            this.logs.ReadOnly = true;
            this.logs.Size = new System.Drawing.Size(803, 406);
            this.logs.TabIndex = 0;
            this.logs.Text = "";
            this.logs.TextChanged += new System.EventHandler(this.richTextBox1_TextChanged);
            // 
            // textBox_Port
            // 
            this.textBox_Port.Location = new System.Drawing.Point(72, 24);
            this.textBox_Port.Name = "textBox_Port";
            this.textBox_Port.Size = new System.Drawing.Size(100, 20);
            this.textBox_Port.TabIndex = 1;
            // 
            // labelPort
            // 
            this.labelPort.AutoSize = true;
            this.labelPort.Location = new System.Drawing.Point(40, 27);
            this.labelPort.Name = "labelPort";
            this.labelPort.Size = new System.Drawing.Size(26, 13);
            this.labelPort.TabIndex = 3;
            this.labelPort.Text = "Port";
            // 
            // folderBrowserDialog1
            // 
            this.folderBrowserDialog1.HelpRequest += new System.EventHandler(this.folderBrowserDialog1_HelpRequest);
            // 
            // button_Listen
            // 
            this.button_Listen.Enabled = false;
            this.button_Listen.Location = new System.Drawing.Point(72, 51);
            this.button_Listen.Name = "button_Listen";
            this.button_Listen.Size = new System.Drawing.Size(100, 23);
            this.button_Listen.TabIndex = 4;
            this.button_Listen.Text = "Listen";
            this.button_Listen.UseVisualStyleBackColor = true;
            this.button_Listen.Click += new System.EventHandler(this.button_Listen_Click_1);
            // 
            // button_browse
            // 
            this.button_browse.Location = new System.Drawing.Point(72, 80);
            this.button_browse.Name = "button_browse";
            this.button_browse.Size = new System.Drawing.Size(147, 29);
            this.button_browse.TabIndex = 5;
            this.button_browse.Text = "Search Directory For Key";
            this.button_browse.UseVisualStyleBackColor = true;
            this.button_browse.Click += new System.EventHandler(this.button_browse_Click);
            // 
            // clientBox
            // 
            this.clientBox.FormattingEnabled = true;
            this.clientBox.Location = new System.Drawing.Point(72, 149);
            this.clientBox.Name = "clientBox";
            this.clientBox.Size = new System.Drawing.Size(100, 147);
            this.clientBox.TabIndex = 6;
            // 
            // button_storage
            // 
            this.button_storage.Location = new System.Drawing.Point(72, 115);
            this.button_storage.Name = "button_storage";
            this.button_storage.Size = new System.Drawing.Size(147, 23);
            this.button_storage.TabIndex = 7;
            this.button_storage.Text = "Search Storage";
            this.button_storage.UseVisualStyleBackColor = true;
            this.button_storage.Click += new System.EventHandler(this.button_storage_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1069, 456);
            this.Controls.Add(this.button_storage);
            this.Controls.Add(this.clientBox);
            this.Controls.Add(this.button_browse);
            this.Controls.Add(this.button_Listen);
            this.Controls.Add(this.labelPort);
            this.Controls.Add(this.textBox_Port);
            this.Controls.Add(this.logs);
            this.Name = "Form1";
            this.Text = "Server";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.RichTextBox logs;
        private System.Windows.Forms.TextBox textBox_Port;
        private System.Windows.Forms.Label labelPort;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog1;
        private System.Windows.Forms.Button button_Listen;
        private System.Windows.Forms.Button button_browse;
        private System.Windows.Forms.ListBox clientBox;
        private System.Windows.Forms.Button button_storage;
    }
}

