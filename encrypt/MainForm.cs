/*
MIT License

Copyright (c) 2025 Arthur Pan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using ICSharpCode.SharpZipLib.Zip;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace FileEncryptor
{
    public class MainForm : Form
    {
        private List<string> files = new List<string>();
        private ListBox? fileListBox;
        private string configFilePath = Path.Combine(Application.StartupPath, "config.json");
        private string defaultFolderPath;
        private ToolStripStatusLabel? statusFilesLabel;
        private ToolStripStatusLabel? statusSizeLabel;
        private string logPath = Path.Combine(Application.StartupPath, "logs", "app_log.txt");
        private CheckBox? secureEncryptionCheckBox;

        public MainForm()
        {
            defaultFolderPath = Path.Combine(Path.GetTempPath(), "FilesToEncrypt_" + Guid.NewGuid().ToString());
            InitializeComponent();
            EnsureDefaultFolderExists();
            Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? string.Empty);
            this.AllowDrop = true;
            this.DragEnter += new DragEventHandler(Form_DragEnter);
            this.DragDrop += new DragEventHandler(Form_DragDrop);
            LogMessage("Application started.");

            if (!File.Exists(configFilePath))
            {
                PromptForPassword();
            }
            else
            {
                string pw = ReadPasswordFromConfig();
                if (string.IsNullOrEmpty(pw))
                {
                    PromptForPassword();
                }
            }

            UpdateStatus();
        }

        private void LogMessage(string message, string level = "INFO")
        {
            string entry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}{Environment.NewLine}";
            File.AppendAllText(logPath, entry);
        }

        private void LogMessage(Exception ex, string message, string level = "ERROR")
        {
            LogMessage($"{message}: {ex.Message}\n{ex.StackTrace}", level);
        }

        private bool IsValidPassword(string pw)
        {
            if (string.IsNullOrEmpty(pw) || pw.Length < 12)
            {
                return false;
            }

            string specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
            bool hasSpecial = pw.Any(c => specialChars.Contains(c));
            if (!hasSpecial)
            {
                return false;
            }

            List<string> weakPasswords = new List<string>
            {
                "password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein", "welcome", "admin", "password1"
            };
            if (weakPasswords.Contains(pw.ToLowerInvariant()))
            {
                return false;
            }

            return true;
        }

        private void PromptForPassword()
        {
            Form prompt = new Form()
            {
                Width = 400,
                Height = 300,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                Text = "Set Encryption Password",
                StartPosition = FormStartPosition.CenterParent
            };

            Label label = new Label() { Left = 20, Top = 20, Text = "Enter password:\n(It will be stored encrypted in config.json)" };
            TextBox passwordTextBox = new TextBox() { Left = 20, Top = 60, Width = 300, PasswordChar = '*' };
            Button showPasswordButton = new Button() { Text = "Show", Left = 330, Top = 60, Width = 50 };
            Label confirmLabel = new Label() { Left = 20, Top = 90, Text = "Confirm password:" };
            TextBox confirmTextBox = new TextBox() { Left = 20, Top = 110, Width = 300, PasswordChar = '*' };
            Button showConfirmButton = new Button() { Text = "Show", Left = 330, Top = 110, Width = 50 };
            Button confirmation = new Button() { Text = "Ok", Left = 150, Width = 100, Top = 150 };

            showPasswordButton.Click += (sender, e) =>
            {
                if (showPasswordButton.Text == "Show")
                {
                    passwordTextBox.PasswordChar = '\0';
                    showPasswordButton.Text = "Hide";
                }
                else
                {
                    passwordTextBox.PasswordChar = '*';
                    showPasswordButton.Text = "Show";
                }
            };

            showConfirmButton.Click += (sender, e) =>
            {
                if (showConfirmButton.Text == "Show")
                {
                    confirmTextBox.PasswordChar = '\0';
                    showConfirmButton.Text = "Hide";
                }
                else
                {
                    confirmTextBox.PasswordChar = '*';
                    showConfirmButton.Text = "Show";
                }
            };

            confirmation.Click += (sender, e) =>
            {
                string pw = passwordTextBox.Text;
                string confirmPw = confirmTextBox.Text;

                if (pw != confirmPw)
                {
                    MessageBox.Show("Passwords do not match.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (string.IsNullOrEmpty(pw))
                {
                    MessageBox.Show("Password cannot be empty.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (!IsValidPassword(pw))
                {
                    MessageBox.Show("Password must be at least 12 characters long, contain at least one special character, and not be a common weak password.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                prompt.Close();
            };

            prompt.Controls.Add(label);
            prompt.Controls.Add(passwordTextBox);
            prompt.Controls.Add(showPasswordButton);
            prompt.Controls.Add(confirmLabel);
            prompt.Controls.Add(confirmTextBox);
            prompt.Controls.Add(showConfirmButton);
            prompt.Controls.Add(confirmation);
            prompt.AcceptButton = confirmation;
            prompt.ShowDialog(this);

            string pwFinal = passwordTextBox.Text;

            byte[] encryptedPw = ProtectedData.Protect(Encoding.UTF8.GetBytes(pwFinal), null, DataProtectionScope.CurrentUser);
            string encryptedPwStr = Convert.ToBase64String(encryptedPw);

            var config = new { Password = encryptedPwStr };
            File.WriteAllText(configFilePath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
            LogMessage("Encrypted password set in config.");
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
                string encryptedPwStr = config!["Password"];
                byte[] encryptedPw = Convert.FromBase64String(encryptedPwStr);
                byte[] pwBytes = ProtectedData.Unprotect(encryptedPw, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(pwBytes);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error reading config file: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                LogMessage(ex, "Error reading config file.");
                return string.Empty;
            }
        }

        private void InitializeComponent()
        {
            this.Text = "文件加密小工具 ver 1.2";
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

            secureEncryptionCheckBox = new CheckBox()
            {
                Text = "Use AES-256 (secure, 3rd-party extractor required)",
                Location = new Point(0, 380),
                Size = new Size(300, 20),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left,
                Checked = false
            };

            importButton.Click += (sender, e) => ImportFiles();
            encryptButton.Click += (sender, e) => EncryptFiles();
            removeButton.Click += (sender, e) => RemoveSelectedFiles();
            clearButton.Click += (sender, e) =>
            {
                files.Clear();
                fileListBox.Items.Clear();
                UpdateStatus();
                LogMessage("File list cleared.");
            };

            StatusStrip statusStrip = new StatusStrip()
            {
                Dock = DockStyle.Bottom
            };

            statusFilesLabel = new ToolStripStatusLabel()
            {
                Text = "Files: 0"
            };

            statusSizeLabel = new ToolStripStatusLabel()
            {
                Text = "Total Size: 0 bytes",
                Spring = true
            };

            statusStrip.Items.Add(statusFilesLabel);
            statusStrip.Items.Add(statusSizeLabel);

            this.Controls.Add(headerPanel);
            this.Controls.Add(fileListLabel);
            this.Controls.Add(fileListBox);
            this.Controls.Add(importButton);
            this.Controls.Add(encryptButton);
            this.Controls.Add(removeButton);
            this.Controls.Add(clearButton);
            this.Controls.Add(secureEncryptionCheckBox);
            this.Controls.Add(statusStrip);

            ToolTip toolTip = new ToolTip();
            toolTip.SetToolTip(importButton, "Select one or more files to add to the encryption list.");
            toolTip.SetToolTip(encryptButton, "Encrypt all imported files into a single password-protected ZIP.");
            toolTip.SetToolTip(removeButton, "Remove the selected files from the list.");
            toolTip.SetToolTip(clearButton, "Clear the list of imported files.");
            toolTip.SetToolTip(secureEncryptionCheckBox, "Enable for stronger AES-256 encryption (more secure, but requires third-party tools like 7-Zip to extract). Disable for compatibility with Windows built-in extractor.");
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
                int addedCount = 0;
                foreach (string file in openFileDialog.FileNames)
                {
                    if (!files.Contains(file))
                    {
                        string destFile = Path.Combine(defaultFolderPath, Path.GetFileName(file));
                        File.Copy(file, destFile, true);
                        files.Add(destFile);
                        fileListBox!.Items.Add(destFile);
                        addedCount++;
                    }
                }
                UpdateStatus();
                LogMessage($"{addedCount} files imported.");
            }
        }

        private void RemoveSelectedFiles()
        {
            if (fileListBox!.SelectedItems.Count > 0)
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
                        LogMessage(ex, $"Error deleting file {item}.");
                    }
                }
                UpdateStatus();
                LogMessage($"{toRemove.Count} files removed.");
            }
        }

        private string ComputeHash(string filePath)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
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
                LogMessage($"Encryption started for {files.Count} files.");

                // Compute original hashes
                Dictionary<string, string> originalHashes = new Dictionary<string, string>();
                foreach (string file in files)
                {
                    string hash = ComputeHash(file);
                    originalHashes[Path.GetFileName(file)] = hash;
                }

                DateTime now = DateTime.Now;
                string defaultFileName = $"encrypted-{now.Year:D4}-{now.Month:D2}-{now.Day:D2}-{now.Hour:D2}-{now.Minute:D2}-{now.Second:D2}-01.zip";

                SaveFileDialog saveFileDialog = new SaveFileDialog()
                {
                    Filter = "ZIP Files (*.zip)|*.zip",
                    Title = "Save Encrypted File",
                    FileName = defaultFileName,
                    AddExtension = true
                };
                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string savePath = saveFileDialog.FileName;
                    if (!Path.GetExtension(savePath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBox.Show("The file must be saved with a .zip extension. Please try again.", "Invalid Extension", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    using (ZipOutputStream zipStream = new ZipOutputStream(File.Create(savePath)))
                    {
                        zipStream.Password = password;
                        zipStream.SetLevel(9); // Best compression

                        foreach (string file in files)
                        {
                            ZipEntry entry = new ZipEntry(Path.GetFileName(file));
                            entry.DateTime = DateTime.Now;
                            entry.IsUnicodeText = true; // Support for Unicode filenames

                            if (secureEncryptionCheckBox!.Checked)
                            {
                                entry.AESKeySize = 256;
                            }
                            else
                            {
                                entry.AESKeySize = 0; // Use ZipCrypto
                            }

                            zipStream.PutNextEntry(entry);

                            using (FileStream streamReader = File.OpenRead(file))
                            {
                                byte[] buffer = new byte[4096];
                                int read;
                                while ((read = streamReader.Read(buffer, 0, buffer.Length)) > 0)
                                {
                                    zipStream.Write(buffer, 0, read);
                                }
                            }
                        }

                        zipStream.Finish();
                    }

                    // Verify the encrypted file
                    string verifyTemp = Path.Combine(Path.GetTempPath(), "Verify_" + Guid.NewGuid().ToString());
                    Directory.CreateDirectory(verifyTemp);
                    bool allGood = true;
                    StringBuilder verificationErrors = new StringBuilder();

                    try
                    {
                        using (ZipFile zipVerify = new ZipFile(savePath))
                        {
                            zipVerify.Password = password;

                            foreach (ZipEntry entry in zipVerify)
                            {
                                if (entry.IsDirectory)
                                {
                                    Directory.CreateDirectory(Path.Combine(verifyTemp, entry.Name));
                                    continue;
                                }

                                string extractedFile = Path.Combine(verifyTemp, entry.Name);
                                Directory.CreateDirectory(Path.GetDirectoryName(extractedFile) ?? string.Empty);

                                using (Stream inputStream = zipVerify.GetInputStream(entry))
                                using (FileStream outputStream = File.Create(extractedFile))
                                {
                                    inputStream.CopyTo(outputStream);
                                }
                            }
                        }

                        foreach (string extractedFile in Directory.GetFiles(verifyTemp))
                        {
                            string fname = Path.GetFileName(extractedFile);
                            if (originalHashes.ContainsKey(fname))
                            {
                                string hash = ComputeHash(extractedFile);
                                if (hash != originalHashes[fname])
                                {
                                    allGood = false;
                                    verificationErrors.AppendLine($"Verification failed for {fname}: hashes do not match.");
                                }
                            }
                            else
                            {
                                allGood = false;
                                verificationErrors.AppendLine($"Verification failed: {fname} not found in original files.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        allGood = false;
                        verificationErrors.AppendLine($"Error during verification: {ex.Message}");
                        LogMessage(ex, "Error during verification.");
                    }
                    finally
                    {
                        Directory.Delete(verifyTemp, true);
                    }

                    if (allGood)
                    {
                        MessageBox.Show($"Encrypted file saved to: {savePath}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        LogMessage($"Encryption completed successfully. Saved to {savePath}.");
                    }
                    else
                    {
                        MessageBox.Show($"Encrypted file saved to: {savePath}, but verification failed:\n{verificationErrors.ToString()}", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        LogMessage($"Encryption saved to {savePath}, but verification failed: {verificationErrors.ToString()}");
                    }

                    files.Clear();
                    fileListBox!.Items.Clear();
                    Directory.Delete(defaultFolderPath, true);
                    UpdateStatus();
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show("Access denied. Please run the application as an administrator or select a different save location.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                LogMessage(ex, "Access denied during encryption.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during encryption: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                LogMessage(ex, "Error during encryption.");
            }
        }

        private void Form_DragEnter(object? sender, DragEventArgs e)
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) ?? false)
                e.Effect = DragDropEffects.Copy;
            else
                e.Effect = DragDropEffects.None;
        }

        private void Form_DragDrop(object? sender, DragEventArgs e)
        {
            if (e.Data == null) return;
            string[]? filePaths = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (filePaths == null) return;

            int addedCount = 0;
            foreach (string filePath in filePaths)
            {
                if (File.Exists(filePath) && !files.Contains(filePath))
                {
                    string destFile = Path.Combine(defaultFolderPath, Path.GetFileName(filePath));
                    File.Copy(filePath, destFile, true);
                    files.Add(destFile);
                    fileListBox!.Items.Add(destFile);
                    addedCount++;
                }
            }
            UpdateStatus();
            LogMessage($"{addedCount} files imported via drag-and-drop.");
        }

        private void UpdateStatus()
        {
            int count = files.Count;
            long totalSize = 0;
            foreach (string file in files)
            {
                totalSize += new FileInfo(file).Length;
            }
            string sizeStr = FormatSize(totalSize);
            statusFilesLabel!.Text = $"Files: {count}";
            statusSizeLabel!.Text = $"Total Size: {sizeStr}";
        }

        private string FormatSize(long bytes)
        {
            string[] sizes = { "bytes", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
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
