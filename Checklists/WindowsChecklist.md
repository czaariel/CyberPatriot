# Windows Checklist CyberPatriot

## Notes and Forensics Question Reference

**Make sure to run powershell in administrator mode and also check version with `(Get-Host).Version`**

When you see the syntax `$args` or `$word`, do not type it verbatim, but instead substitute in what is necessary.

For decrypting files, use: https://cryptii.com/ 


## Checklist

#### Initial Phase

1. Read the readme

      Note down which ports/users are allowed.
      
1. **Do forensics questions**

      If you use script/checklist first, you may break the system!

1. Read the readme again!

1. Run `mainwindowscript.ps1` in powerhsell in administrator mode

#### Post-Script Phase

1. Unwanted Programs
      
      Once the script is done running, you need to go and locate a file called `InstalledPrograms-PS.txt`. It will be found at `C:\Users\$whoyouareloggedinas\Documents\InstalledPrograms-PS.txt`. Once you find this, open it to find all the non-default programs on the computer. Compare it with the readme to see what software you do not need. To uninstall these programs, do:

      ````
      Uninstall-Program -ProgramName $unwantedprogram -UninstallAllSimilarlyNamedPackages
      ````
