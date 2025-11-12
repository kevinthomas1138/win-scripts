diff --git a/README.md b/README.md
index de335ab3615fb91acd731329af2fcb0c272aa4a1..7f153c60021f9c891fd66b425bfee354556ed50b 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,46 @@
 # win-scripts
-Windows Scripts used for starting and cleaning up a new computer build
+
+Windows scripts used for starting and cleaning up a new computer build.
+
+## Available scripts
+
+### `scripts/de-bloat-3.ps1`
+
+A defensive Windows 10/11 de-bloat script that removes pre-installed AppX packages,
+disables telemetry related scheduled tasks, turns off rarely used optional features, and
+optionally uninstalls OneDrive.  The script performs extensive validation before making
+changes so that missing packages or already-disabled features do not trigger errors.
+
+#### Download
+
+If you just want the standalone script without cloning the entire repository, download
+`downloads/de-bloat-3.ps1` directly from the repo.  On GitHub you can click the file and
+use the **Download raw file** button, or fetch it with PowerShell:
+
+```powershell
+Invoke-WebRequest -Uri "https://raw.githubusercontent.com/<your-fork-or-org>/win-scripts/<branch>/downloads/de-bloat-3.ps1" -OutFile "de-bloat-3.ps1"
+```
+
+#### Usage
+
+```powershell
+# From an elevated PowerShell window
+Set-Location path\to\win-scripts
+
+# Optional: preview without making changes
+./scripts/de-bloat-3.ps1 -WhatIf
+
+# Perform the cleanup without removing scheduled tasks
+./scripts/de-bloat-3.ps1 -SkipScheduledTasks
+```
+
+The script supports the following switches when you want to skip parts of the routine:
+
+- `-SkipAppxPackages`
+- `-SkipOptionalFeatures`
+- `-SkipScheduledTasks`
+- `-SkipOneDriveRemoval`
+
+Use the built-in `-WhatIf` or `-Confirm` switches for dry runs or interactive
+confirmation.  Logging is written directly to the console for easy auditing during the
+cleanup process.
