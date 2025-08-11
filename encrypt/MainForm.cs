```csharp
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
        private List<string> originalFiles = new List<string>();
        private List<string> filesToEncrypt = new List<string>();
        private ListBox fileListBox;
        private string configFilePath = Path.Combine(Application.StartupPath, "config.json");
        private string defaultFolderPath;

        public MainForm()
        {
            defaultFolderPath = Path.Combine(Path.GetTempPath(), "FilesToEncrypt_" + Guid.NewGuid().ToString());
            InitializeComponent();
            CreateConfigFileIfNotExists();
            EnsureDefaultFolderExists();
            this.AllowDrop = true;
            this.DragEnter += new DragEventHandler(Form_DragEnter);
            this.DragDrop += new DragEventHandler(Form_DragDrop);
            this.FormClosing += new FormClosingEventHandler(Form_FormClosing);
        }

        private void Form_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (Directory.Exists(defaultFolderPath))
            {
                try
                {
                    Directory.Delete(defaultFolderPath, true);
                }
                catch { } // Silent fail to avoid interrupting close
            }
        }

        private void CreateConfigFileIfNotExists()
        {
            if (!File.Exists(configFilePath))
            {
                string password = PromptForPassword();
                if (string.IsNullOrEmpty(password))
                {
                    MessageBox.Show("Password cannot be empty. Application will exit.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Application.Exit();
                    return;
                }
                var config = new { Password = password };
                File.WriteAllText(configFilePath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
            }
        }

        private string PromptForPassword()
        {
            Form prompt = new Form()
            {
                Width = 300,
                Height = 150,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                Text = "Set Encryption Password",
                StartPosition = FormStartPosition.CenterScreen
            };
            Label label = new Label() { Left = 20, Top = 20, Text = "Enter a password:" };
            TextBox textBox = new TextBox() { Left = 20, Top = 40, Width = 240, UseSystemPasswordChar = true };
            Button confirmation = new Button() { Text = "OK", Left = 100, Width = 100, Top = 70, DialogResult = DialogResult.OK };
            confirmation.Click += (sender, e) => { prompt.Close(); };
            prompt.Controls.Add(label);
            prompt.Controls.Add(textBox);
            prompt.Controls.Add(confirmation);
            prompt.AcceptButton = confirmation;

            return prompt.ShowDialog() == DialogResult.OK ? textBox.Text : string.Empty;
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
            clearButton.Click += (sender, e) => ClearFileList();

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

        private string GetUniqueDestFile(string filename)
        {
            string dest = Path.Combine(defaultFolderPath, filename);
            if (!File.Exists(dest)) return dest;

            string name = Path.GetFileNameWithoutExtension(filename);
            string ext = Path.GetExtension(filename);
            int i = 1;
            while (true)
            {
                string newName = $"{name} ({i}){ext}";
                dest = Path.Combine(defaultFolderPath, newName);
                if (!File.Exists(dest)) return dest;
                i++;
            }
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
                    if (!originalFiles.Contains(file))
                    {
                        originalFiles.Add(file);
                        string filename = Path.GetFileName(file);
                        string destFile = GetUniqueDestFile(filename);
                        File.Copy(file, destFile, false);
                        filesToEncrypt.Add(destFile);
                        fileListBox.Items.Add(file);
                    }
                }
            }
        }

        private void RemoveSelectedFiles()
        {
            if (fileListBox.SelectedItems.Count > 0)
            {
                List<int> indicesToRemove = new List<int>();
                foreach (int selectedIndex in fileListBox.SelectedIndices)
                {
                    indicesToRemove.Add(selectedIndex);
                }
                indicesToRemove.Sort((a, b) => b.CompareTo(a)); // Remove from end to avoid index shifts

                foreach (int index in indicesToRemove)
                {
                    string dest = filesToEncrypt[index];
                    originalFiles.RemoveAt(index);
                    filesToEncrypt.RemoveAt(index);
                    fileListBox.Items.RemoveAt(index);
                    try
                    {
                        File.Delete(dest);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Error deleting file {dest}: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void ClearFileList()
        {
            foreach (string dest in filesToEncrypt)
            {
                try
                {
                    File.Delete(dest);
                }
                catch { } // Silent fail
            }
            originalFiles.Clear();
            filesToEncrypt.Clear();
            fileListBox.Items.Clear();
        }

        private void EncryptFiles()
        {
            string password = ReadPasswordFromConfig();
            if (string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Failed to read encryption password from config.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (filesToEncrypt.Count == 0)
            {
                MessageBox.Show("No files imported.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                DateTime now = DateTime.Now;
                string defaultFileName = $"encrypted-{now.Year:D4}-{now.Month:D2}-{now.Day:D2}-{now.Hour:D2}-{now.Minute:D2}-{now.Second:D2}-01.zip";

                SaveFileDialog saveFileDialog = new SaveFileDialog()
                {
                    Filter = "ZIP Files (*.zip)|*.zip",
                    Title = "Save Encrypted File",
                    FileName = defaultFileName
                };

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    using (ZipFile zip = new ZipFile())
                    {
                        zip.UseUnicodeAsNecessary = true;
                        zip.Password = password;
                        zip.Encryption = EncryptionAlgorithm.WinZipAes256;
                        foreach (string file in filesToEncrypt)
                        {
                            zip.AddFile(file, "");
                        }
                        zip.Save(saveFileDialog.FileName);
                    }
                    MessageBox.Show($"Encrypted file saved to: {saveFileDialog.FileName}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    ClearFileList();
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
                if (File.Exists(filePath) && !originalFiles.Contains(filePath))
                {
                    originalFiles.Add(filePath);
                    string filename = Path.GetFileName(filePath);
                    string destFile = GetUniqueDestFile(filename);
                    File.Copy(filePath, destFile, false);
                    filesToEncrypt.Add(destFile);
                    fileListBox.Items.Add(filePath);
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
```
