﻿namespace BizHawk.Client.EmuHawk
{
	partial class FirmwaresConfigInfo
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



		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			this.components = new System.ComponentModel.Container();
			this.lvOptions = new System.Windows.Forms.ListView();
			this.colSize = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
			this.colHash = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
			this.colStandardFilename = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
			this.colDescription = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
			this.colInfo = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
			this.imageList1 = new System.Windows.Forms.ImageList(this.components);
			this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
			this.label1 = new System.Windows.Forms.Label();
			this.btnClose = new System.Windows.Forms.Button();
			this.flowLayoutPanel1 = new System.Windows.Forms.FlowLayoutPanel();
			this.label2 = new System.Windows.Forms.Label();
			this.lblFirmware = new System.Windows.Forms.Label();
			this.lvmiOptionsContextMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
			this.tsmiOptionsCopy = new System.Windows.Forms.ToolStripMenuItem();
			this.toolTip1 = new System.Windows.Forms.ToolTip(this.components);
			this.tableLayoutPanel1.SuspendLayout();
			this.flowLayoutPanel1.SuspendLayout();
			this.lvmiOptionsContextMenuStrip.SuspendLayout();
			this.SuspendLayout();
			// 
			// lvOptions
			// 
			this.lvOptions.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.colSize,
            this.colHash,
            this.colStandardFilename,
            this.colDescription,
            this.colInfo});
			this.lvOptions.Dock = System.Windows.Forms.DockStyle.Fill;
			this.lvOptions.FullRowSelect = true;
			this.lvOptions.GridLines = true;
			this.lvOptions.Location = new System.Drawing.Point(3, 29);
			this.lvOptions.Name = "lvOptions";
			this.lvOptions.Size = new System.Drawing.Size(722, 402);
			this.lvOptions.SmallImageList = this.imageList1;
			this.lvOptions.TabIndex = 0;
			this.lvOptions.UseCompatibleStateImageBehavior = false;
			this.lvOptions.View = System.Windows.Forms.View.Details;
			this.lvOptions.KeyDown += new System.Windows.Forms.KeyEventHandler(this.LvOptions_KeyDown);
			this.lvOptions.MouseClick += new System.Windows.Forms.MouseEventHandler(this.LvOptions_MouseClick);
			// 
			// colSize
			// 
			this.colSize.Text = "Size";
			this.colSize.Width = 74;
			// 
			// colHash
			// 
			this.colHash.Text = "Hash";
			this.colHash.Width = 251;
			// 
			// colStandardFilename
			// 
			this.colStandardFilename.Text = "Standard Filename";
			this.colStandardFilename.Width = 175;
			// 
			// colDescription
			// 
			this.colDescription.Text = "Description";
			this.colDescription.Width = 214;
			// 
			// colInfo
			// 
			this.colInfo.Text = "Info";
			this.colInfo.Width = 165;
			// 
			// imageList1
			// 
			this.imageList1.ColorDepth = System.Windows.Forms.ColorDepth.Depth8Bit;
			this.imageList1.ImageSize = new System.Drawing.Size(16, 16);
			this.imageList1.TransparentColor = System.Drawing.Color.Transparent;
			// 
			// tableLayoutPanel1
			// 
			this.tableLayoutPanel1.ColumnCount = 1;
			this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
			this.tableLayoutPanel1.Controls.Add(this.label1, 0, 1);
			this.tableLayoutPanel1.Controls.Add(this.lvOptions, 0, 2);
			this.tableLayoutPanel1.Controls.Add(this.btnClose, 0, 3);
			this.tableLayoutPanel1.Controls.Add(this.flowLayoutPanel1, 0, 0);
			this.tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
			this.tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
			this.tableLayoutPanel1.Name = "tableLayoutPanel1";
			this.tableLayoutPanel1.RowCount = 4;
			this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
			this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle());
			this.tableLayoutPanel1.Size = new System.Drawing.Size(728, 469);
			this.tableLayoutPanel1.TabIndex = 1;
			// 
			// label1
			// 
			this.label1.AutoSize = true;
			this.label1.Location = new System.Drawing.Point(3, 13);
			this.label1.Name = "label1";
			this.label1.Size = new System.Drawing.Size(122, 13);
			this.label1.TabIndex = 1;
			this.label1.Text = "Options for this firmware:";
			// 
			// btnClose
			// 
			this.btnClose.Anchor = System.Windows.Forms.AnchorStyles.Right;
			this.btnClose.AutoSize = true;
			this.btnClose.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.btnClose.Location = new System.Drawing.Point(669, 440);
			this.btnClose.Margin = new System.Windows.Forms.Padding(6);
			this.btnClose.Name = "btnClose";
			this.btnClose.Size = new System.Drawing.Size(53, 23);
			this.btnClose.TabIndex = 2;
			this.btnClose.Text = "Close";
			this.btnClose.UseVisualStyleBackColor = true;
			// 
			// flowLayoutPanel1
			// 
			this.flowLayoutPanel1.AutoSize = true;
			this.flowLayoutPanel1.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.flowLayoutPanel1.Controls.Add(this.label2);
			this.flowLayoutPanel1.Controls.Add(this.lblFirmware);
			this.flowLayoutPanel1.Location = new System.Drawing.Point(0, 0);
			this.flowLayoutPanel1.Margin = new System.Windows.Forms.Padding(0);
			this.flowLayoutPanel1.Name = "flowLayoutPanel1";
			this.flowLayoutPanel1.Size = new System.Drawing.Size(99, 13);
			this.flowLayoutPanel1.TabIndex = 3;
			// 
			// label2
			// 
			this.label2.AutoSize = true;
			this.label2.Location = new System.Drawing.Point(3, 0);
			this.label2.Name = "label2";
			this.label2.Size = new System.Drawing.Size(52, 13);
			this.label2.TabIndex = 0;
			this.label2.Text = "Firmware:";
			// 
			// lblFirmware
			// 
			this.lblFirmware.AutoSize = true;
			this.lblFirmware.Location = new System.Drawing.Point(61, 0);
			this.lblFirmware.Name = "lblFirmware";
			this.lblFirmware.Size = new System.Drawing.Size(35, 13);
			this.lblFirmware.TabIndex = 1;
			this.lblFirmware.Text = "label3";
			// 
			// lvmiOptionsContextMenuStrip
			// 
			this.lvmiOptionsContextMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tsmiOptionsCopy});
			this.lvmiOptionsContextMenuStrip.Name = "lvmiOptionsContextMenuStrip";
			this.lvmiOptionsContextMenuStrip.Size = new System.Drawing.Size(100, 26);
			// 
			// tsmiOptionsCopy
			// 
			this.tsmiOptionsCopy.Name = "tsmiOptionsCopy";
			this.tsmiOptionsCopy.Size = new System.Drawing.Size(99, 22);
			this.tsmiOptionsCopy.Text = "&Copy";
			this.tsmiOptionsCopy.Click += new System.EventHandler(this.TsmiOptionsCopy_Click);
			// 
			// FirmwaresConfigInfo
			// 
			this.AcceptButton = this.btnClose;
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.CancelButton = this.btnClose;
			this.ClientSize = new System.Drawing.Size(728, 469);
			this.Controls.Add(this.tableLayoutPanel1);
			this.Name = "FirmwaresConfigInfo";
			this.ShowIcon = false;
			this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
			this.Text = "Firmware Info";
			this.tableLayoutPanel1.ResumeLayout(false);
			this.tableLayoutPanel1.PerformLayout();
			this.flowLayoutPanel1.ResumeLayout(false);
			this.flowLayoutPanel1.PerformLayout();
			this.lvmiOptionsContextMenuStrip.ResumeLayout(false);
			this.ResumeLayout(false);

		}



		private System.Windows.Forms.ColumnHeader colHash;
		private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
		private System.Windows.Forms.Label label1;
		private System.Windows.Forms.Button btnClose;
		private System.Windows.Forms.ColumnHeader colStandardFilename;
		private System.Windows.Forms.ColumnHeader colDescription;
		public System.Windows.Forms.ListView lvOptions;
		private System.Windows.Forms.FlowLayoutPanel flowLayoutPanel1;
		private System.Windows.Forms.Label label2;
		public System.Windows.Forms.Label lblFirmware;
		private System.Windows.Forms.ContextMenuStrip lvmiOptionsContextMenuStrip;
		private System.Windows.Forms.ToolStripMenuItem tsmiOptionsCopy;
		private System.Windows.Forms.ColumnHeader colInfo;
		private System.Windows.Forms.ImageList imageList1;
		private System.Windows.Forms.ColumnHeader colSize;
		private System.Windows.Forms.ToolTip toolTip1;
	}
}