using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using ZipExtractor.Properties;

namespace ZipExtractor;

public partial class FormMain : Form
{
	private const int MaxRetries = 2;
	protected StringBuilder LogBuilder { get; init; } = new();
	protected BackgroundWorker BackgroundTask { get; init; }

	public FormMain()
	{
		BackgroundTask = new BackgroundWorker
		{
			WorkerReportsProgress = true,
			WorkerSupportsCancellation = true
		};

		InitializeComponent();
	}

	private void FormMain_Shown(object sender, EventArgs e)
	{
		string zipPath = null;
		string extractionPath = null;
		string currentExe = null;
		string updatedExe = null;
		bool clearAppDirectory = false;
		string commandLineArgs = null;
		string serviceName = null;

		LogBuilder.AppendLine(DateTime.Now.ToString("F"));
		LogBuilder.AppendLine();
		LogBuilder.AppendLine("ZipExtractor started with following command line arguments.");

		string[] args = Environment.GetCommandLineArgs();
		for (var index = 0; index < args.Length; index++)
		{
			string arg = args[index].ToLower();
			switch (arg)
			{
				case "--input":
					zipPath = args[index + 1];
					break;

				case "--output":
					extractionPath = args[index + 1];
					break;

				case "--current-exe":
					currentExe = args[index + 1];
					break;

				case "--updated-exe":
					updatedExe = args[index + 1];
					break;

				case "--clear":
					clearAppDirectory = true;
					break;

				case "--service-name":
					serviceName = args[index + 1];
					break;

				case "--args":
					commandLineArgs = args[index + 1];
					break;
			}

			LogBuilder.AppendLine($"[{index}] {arg}");
		}

		LogBuilder.AppendLine();

		if (string.IsNullOrEmpty(zipPath) || string.IsNullOrEmpty(extractionPath) || string.IsNullOrEmpty(currentExe))
		{
			return;
		}

		// Extract all the files.
		BackgroundTask.DoWork += (_, eventArgs) =>
		{
			LogBuilder.AppendLine("BackgroundWorker started successfully.");

			if (string.IsNullOrWhiteSpace(serviceName) is false)
			{
				StopService(serviceName, 5);
			}
			else
			{ 
				foreach (Process process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(currentExe)))
					try
					{
						if (process.MainModule is { FileName: not null } && process.MainModule.FileName.Equals(currentExe))
						{
							LogBuilder.AppendLine("Waiting for application process to exit...");

							BackgroundTask.ReportProgress(0, "Waiting for application to exit...");
							process.WaitForExit();
						}
					}
					catch (Exception exception)
					{
						Debug.WriteLine(exception.Message);
					}
			}


			// Ensures that the last character on the extraction path
			// is the directory separator char.
			// Without this, a malicious zip file could try to traverse outside of the expected
			// extraction path.
			if (!extractionPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
			{
				extractionPath += Path.DirectorySeparatorChar;
			}

			ZipArchive archive = ZipFile.OpenRead(zipPath);

			ReadOnlyCollection<ZipArchiveEntry> entries = archive.Entries;

			try
			{
				var progress = 0;

				if (clearAppDirectory)
				{
					LogBuilder.AppendLine($"Removing all files and folders from \"{extractionPath}\".");
					var directoryInfo = new DirectoryInfo(extractionPath);

					foreach (FileInfo file in directoryInfo.GetFiles())
					{
						LogBuilder.AppendLine($"Removing a file located at \"{file.FullName}\".");
						BackgroundTask.ReportProgress(0, string.Format(Resources.Removing, file.FullName));
						file.Delete();
					}

					foreach (DirectoryInfo directory in directoryInfo.GetDirectories())
					{
						LogBuilder.AppendLine(
							$"Removing a directory located at \"{directory.FullName}\" and all its contents.");
						BackgroundTask.ReportProgress(0, string.Format(Resources.Removing, directory.FullName));
						directory.Delete(true);
					}
				}

				LogBuilder.AppendLine($"Found total of {entries.Count} files and folders inside the zip file.");

				for (var index = 0; index < entries.Count; index++)
				{
					if (BackgroundTask.CancellationPending)
					{
						eventArgs.Cancel = true;
						break;
					}

					ZipArchiveEntry entry = entries[index];

					string currentFile = string.Format(Resources.CurrentFileExtracting, entry.FullName);
					BackgroundTask.ReportProgress(progress, currentFile);
					var retries = 0;
					var notCopied = true;
					while (notCopied)
					{
						var filePath = string.Empty;
						try
						{
							filePath = Path.Combine(extractionPath, entry.FullName);
							if (!entry.IsDirectory())
							{
								string parentDirectory = Path.GetDirectoryName(filePath);
								if (parentDirectory != null)
								{
									if (!Directory.Exists(parentDirectory))
									{
										Directory.CreateDirectory(parentDirectory);
									}
								}
								else
								{
									throw new ArgumentNullException($"parentDirectory is null for \"{filePath}\"!");
								}

								using (Stream destination = File.Open(filePath, FileMode.OpenOrCreate, FileAccess.Write,
										   FileShare.None))
								{
									using Stream stream = entry.Open();
									stream.CopyTo(destination);
									destination.SetLength(destination.Position);
								}

								File.SetLastWriteTime(filePath, entry.LastWriteTime.DateTime);
							}

							notCopied = false;
						}
						catch (IOException exception)
						{

							if (string.IsNullOrWhiteSpace(serviceName) is false)
							{
								StopService(serviceName, progress);
							}
							else
							{ 
								const int errorSharingViolation = 0x20;
								const int errorLockViolation = 0x21;
								int errorCode = Marshal.GetHRForException(exception) & 0x0000FFFF;
								if (errorCode is not (errorSharingViolation or errorLockViolation))
								{
									throw;
								}

								retries++;
								if (retries > MaxRetries)
								{
									throw;
								}

								List<Process> lockingProcesses = null;
								if (Environment.OSVersion.Version.Major >= 6 && retries >= 2)
								{
									try
									{
										lockingProcesses = FileUtil.WhoIsLocking(filePath);
									}
									catch (Exception)
									{
										// ignored
									}
								}

								if (lockingProcesses == null)
								{
									Thread.Sleep(5000);
									continue;
								}

								foreach (Process lockingProcess in lockingProcesses)
								{
									DialogResult dialogResult = MessageBox.Show(this,
										string.Format(Resources.FileStillInUseMessage,
											lockingProcess.ProcessName, filePath),
										Resources.FileStillInUseCaption,
										MessageBoxButtons.RetryCancel, MessageBoxIcon.Error);
									if (dialogResult == DialogResult.Cancel)
									{
										throw;
									}
								}
							}
						}
					}

					progress = (index + 1) * 100 / entries.Count;
					BackgroundTask.ReportProgress(progress, currentFile);

					LogBuilder.AppendLine($"{currentFile} [{progress}%]");
				}
			}
			finally
			{
				archive.Dispose();
			}
		};

		BackgroundTask.ProgressChanged += (_, eventArgs) =>
		{
			progressBar.Value = eventArgs.ProgressPercentage;
			textBoxInformation.Text = eventArgs.UserState?.ToString();
			if (textBoxInformation.Text == null)
			{
				return;
			}

			textBoxInformation.SelectionStart = textBoxInformation.Text.Length;
			textBoxInformation.SelectionLength = 0;
		};

		BackgroundTask.RunWorkerCompleted += (_, eventArgs) =>
		{
			try
			{
				if (eventArgs.Error != null)
				{
					throw eventArgs.Error;
				}

				if (eventArgs.Cancelled)
				{
					return;
				}

				textBoxInformation.Text = @"Finished";
				try
				{
					if (string.IsNullOrWhiteSpace(serviceName) is false)
					{
						StartService(serviceName);
					}
					else
					{ 
						string executablePath = string.IsNullOrWhiteSpace(updatedExe)
							? currentExe
							: Path.Combine(extractionPath, updatedExe);
						var processStartInfo = new ProcessStartInfo(executablePath);
						if (!string.IsNullOrEmpty(commandLineArgs))
						{
							processStartInfo.Arguments = commandLineArgs;
						}

						Process.Start(processStartInfo);
					}
					LogBuilder.AppendLine("Successfully launched the updated application.");
				}
				catch (Win32Exception exception)
				{
					if (exception.NativeErrorCode != 1223)
					{
						throw;
					}
				}
			}
			catch (Exception exception)
			{
				LogBuilder.AppendLine();
				LogBuilder.AppendLine(exception.ToString());

				MessageBox.Show(this, exception.Message, exception.GetType().ToString(),
					MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
			finally
			{
				LogBuilder.AppendLine();
				Application.Exit();
			}
		};

		BackgroundTask.RunWorkerAsync();
	}

	private void StartService(string serviceName, string? arguments = null)
	{
		// Execute "sc start {serviceName}" and wait for it to finish
		LogBuilder.AppendLine($"Starting service \"{serviceName}\".");

		Process process = Process.Start(new ProcessStartInfo
		{
			FileName = "sc.exe",
			Arguments = $"start \"{serviceName}\"",
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			ArgumentList = { arguments },
			UseShellExecute = false,
			CreateNoWindow = true,
		});

		process.WaitForExit();
	}

	private void StopService(string serviceName, int progress)
	{
		// Execute "sc stop {serviceName}" and wait for it to finish.
		LogBuilder.AppendLine($"Stopping service \"{serviceName}\".");
		BackgroundTask.ReportProgress(progress, $"Stopping service \"{serviceName}\".");
		Process process = Process.Start(new ProcessStartInfo
		{
			FileName = "sc.exe",
			Arguments = $"stop \"{serviceName}\"",
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			UseShellExecute = false,
			CreateNoWindow = true
		});

		process.WaitForExit();
	}

	private void FormMain_FormClosing(object sender, FormClosingEventArgs e)
	{
		BackgroundTask?.CancelAsync();

		LogBuilder.AppendLine();
		File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ZipExtractor.log"),
			LogBuilder.ToString());
	}
}
