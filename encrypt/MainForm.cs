using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using Ionic.Zip;
using System.Text.Json;

namespace FileEncryptor
{
    public class MainForm : Form
    {
        private List<string> files = new List<string>();
        private ListBox fileListBox;
        private string configFilePath = Path.Combine(Application.StartupPath, "config.json");
        private string defaultFolderPath;
        private const string fixedPassword = "XXXXXXXXXXX"; // input the password

        public MainForm()
        {
            defaultFolderPath = Path.Combine(Path.GetTempPath(), "FilesToEncrypt_" + Guid.NewGuid().ToString());
            InitializeComponent();
            CreateConfigFileIfNotExists();
            EnsureDefaultFolderExists();
            this.AllowDrop = true;
            this.DragEnter += new DragEventHandler(Form_DragEnter);
            this.DragDrop += new DragEventHandler(Form_DragDrop);
        }

        private void CreateConfigFileIfNotExists()
        {
            if (!File.Exists(configFilePath))
            {
                var config = new { Password = fixedPassword };
                File.WriteAllText(configFilePath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        private void EnsureDefaultFolderExists()
        {
            if (!Directory.Exists(defaultFolderPath))
            {
                Directory.CreateDirectory(defaultFolderPath);
            }
        }

        private string ReadPasswordFromConfig()
        {
            try
            {
                string json = File.ReadAllText(configFilePath);
                var config = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                return config["Password"];
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error reading config file: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return string.Empty;
            }
        }

        private void InitializeComponent()
        {
            this.Text = "文件加密小工具";
            this.Size = new System.Drawing.Size(600, 450);
            this.MinimumSize = new System.Drawing.Size(400, 350);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.Padding = new Padding(10);

            Panel headerPanel = new Panel()
            {
                Location = new Point(0, 0),
                Size = new Size(this.ClientSize.Width, 50),
                BackColor = Color.White,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            Label titleLabel = new Label()
            {
                Text = "文件加密小工具",
                ForeColor = Color.Blue,
                Font = new Font("Arial", 16, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(10, 10)
            };

            headerPanel.Controls.Add(titleLabel);

            Label fileListLabel = new Label()
            {
                Text = "Imported Files:",
                Location = new Point(0, 60),
                AutoSize = true
            };

            fileListBox = new ListBox()
            {
                Location = new Point(0, 80),
                Size = new Size(570, 260),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                IntegralHeight = false,
                HorizontalScrollbar = true,
                SelectionMode = SelectionMode.MultiExtended
            };

            Button importButton = new Button()
            {
                Text = "Import Files",
                Location = new Point(0, 350),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left,
                FlatStyle = FlatStyle.Flat
            };

            Button encryptButton = new Button()
            {
                Text = "Encrypt",
                Location = new Point(110, 350),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left,
                FlatStyle = FlatStyle.Flat
            };

            Button removeButton = new Button()
            {
                Text = "Remove Selected",
                Location = new Point(220, 350),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left,
                FlatStyle = FlatStyle.Flat
            };

            Button clearButton = new Button()
            {
                Text = "Clear List",
                Location = new Point(350, 350),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left,
                FlatStyle = FlatStyle.Flat
            };

            importButton.Click += (sender, e) => ImportFiles();
            encryptButton.Click += (sender, e) => EncryptFiles();
            removeButton.Click += (sender, e) => RemoveSelectedFiles();
            clearButton.Click += (sender, e) =>
            {
                files.Clear();
                fileListBox.Items.Clear();
            };

            this.Controls.Add(headerPanel);
            this.Controls.Add(fileListLabel);
            this.Controls.Add(fileListBox);
            this.Controls.Add(importButton);
            this.Controls.Add(encryptButton);
            this.Controls.Add(removeButton);
            this.Controls.Add(clearButton);

            ToolTip toolTip = new ToolTip();
            toolTip.SetToolTip(importButton, "Select one or more files to add to the encryption list.");
            toolTip.SetToolTip(encryptButton, "Encrypt all imported files into a single password-protected ZIP.");
            toolTip.SetToolTip(removeButton, "Remove the selected files from the list.");
            toolTip.SetToolTip(clearButton, "Clear the list of imported files.");
        }

        private void ImportFiles()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog()
            {
                Multiselect = true,
                Title = "Select Files to Encrypt"
            };
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                foreach (string file in openFileDialog.FileNames)
                {
                    if (!files.Contains(file))
                    {
                        string destFile = Path.Combine(defaultFolderPath, Path.GetFileName(file));
                        File.Copy(file, destFile, true);
                        files.Add(destFile);
                        fileListBox.Items.Add(destFile);
                    }
                }
            }
        }

        private void RemoveSelectedFiles()
        {
            if (fileListBox.SelectedItems.Count > 0)
            {
                List<string> toRemove = new List<string>();
                foreach (string selected in fileListBox.SelectedItems)
                {
                    toRemove.Add(selected);
                }
                foreach (string item in toRemove)
                {
                    files.Remove(item);
                    fileListBox.Items.Remove(item);
                    try
                    {
                        File.Delete(item);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Error deleting file {item}: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void EncryptFiles()
        {
            string password = ReadPasswordFromConfig();
            if (string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Failed to read encryption password from config.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (files.Count == 0)
            {
                MessageBox.Show("No files imported.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog()
                {
                    Filter = "ZIP Files (*.zip)|*.zip",
                    Title = "Save Encrypted File",
                    FileName = "encrypted_files.zip"
                };
                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    using (ZipFile zip = new ZipFile())
                    {
                        zip.Password = password;
                        zip.Encryption = EncryptionAlgorithm.WinZipAes256;
                        foreach (string file in files)
                        {
                            zip.AddFile(file, "");
                        }
                        zip.Save(saveFileDialog.FileName);
                    }
                    MessageBox.Show($"Encrypted file saved to: {saveFileDialog.FileName}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    files.Clear();
                    fileListBox.Items.Clear();
                    Directory.Delete(defaultFolderPath, true);
                }
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Access denied. Please run the application as an administrator or select a different save location.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during encryption: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Form_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
            else
                e.Effect = DragDropEffects.None;
        }

        private void Form_DragDrop(object sender, DragEventArgs e)
        {
            string[] filePaths = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string filePath in filePaths)
            {
                if (File.Exists(filePath) && !files.Contains(filePath))
                {
                    string destFile = Path.Combine(defaultFolderPath, Path.GetFileName(filePath));
                    File.Copy(filePath, destFile, true);
                    files.Add(destFile);
                    fileListBox.Items.Add(destFile);
                }
            }
        }

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

}
