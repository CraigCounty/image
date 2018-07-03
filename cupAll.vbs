if wscript.arguments.length = 0 then
      set objshell = createobject("shell.application")
      objshell.shellexecute "wscript.exe", chr(34) & _
      wscript.scriptfullname & chr(34) & " uac", "", "runas", 0
else
      set fso = createobject("scripting.filesystemobject")
      set shell = createobject("wscript.shell")
      shell.run ("powershell.exe -nologo -file ") & replace(wscript.scriptname,"." & fso.getextensionname(wscript.scriptname),".ps1"),0
end if