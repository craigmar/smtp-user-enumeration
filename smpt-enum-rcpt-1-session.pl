#modified smtp-enum to allow multiple queries in a single session
use strict;
use Socket;
use IO::Handle;
use IO::Select;
use IO::Socket::INET;
use Getopt::Std;
$| = 1;
my $VERSION        = "1";
my $debug          = 0;
my $verbose        = 0;
my $smtp_port      = 25;
my @usernames      = ();
my @hosts          = ();
my $recursive_flag = 1;
my $query_timeout  = 5;
my $mode           = "RCPT";
my $from_address   = 'a@a.com';
my $start_time     = time();
my $end_time;
my %opts;
my $usage=<<USAGE;

Usage: smtp-user-enum.pl [options] ( -u username | -U file-of-usernames ) ( -t host | -T file-of-targets )

options are:
   
	-M mode  Method to use for username guessing EXPN, VRFY or RCPT (default: $mode)
	-u user  Check if user exists on remote system
	-f addr  MAIL FROM email address.  Used only in "RCPT TO" mode (default: $from_address)
        -D dom   Domain to append to supplied user list to make email addresses (Default: none)
                 Use this option when you want to guess valid email addresses instead of just usernames
                 e.g. "-D example.com" would guess foo\@example.com, bar\@example.com, etc.  Instead of 
                      simply the usernames foo and bar.
	-U file  File of usernames to check via smtp service
	-t host  Server host running smtp service
	-T file  File of hostnames running the smtp service
	-p port  TCP port on which smtp service runs (default: $smtp_port)
	-d       Debugging output
	-t n     Wait a maximum of n seconds for reply (default: $query_timeout)
	-v       Verbose
	-h       This help message

Also see smtp-user-enum-user-docs.pdf from the smtp-user-enum tar ball.

Examples:

\$ smtp-user-enum.pl -M VRFY -U users.txt -t 10.0.0.1
\$ smtp-user-enum.pl -M EXPN -u admin1 -t 10.0.0.1
\$ smtp-user-enum.pl -M RCPT -U users.txt -T mail-server-ips.txt
\$ smtp-user-enum.pl -M EXPN -D example.com -U users.txt -t 10.0.0.1

USAGE

getopts('m:u:U:s:S:r:dt:vhM:f:D:p:', \%opts);

# Print help message if required
if ($opts{'h'}) {
	print $usage;
	exit 0;
}

my $username       = $opts{'u'} if $opts{'u'};
my $username_file  = $opts{'U'} if $opts{'U'};
my $host           = $opts{'t'} if $opts{'t'};
my $host_file      = $opts{'T'} if $opts{'T'};
my $file           = $opts{'f'} if $opts{'f'};
my $domain = ""; $domain = $opts{'D'} if $opts{'D'};

$verbose        = $opts{'v'} if $opts{'v'};
$debug          = $opts{'d'} if $opts{'d'};
$smtp_port      = $opts{'p'} if $opts{'p'};
$mode           = $opts{'M'} if $opts{'M'};
$from_address   = $opts{'f'} if $opts{'f'};

# Check for illegal option combinations
unless ((defined($username) or defined($username_file)) and (defined($host) or defined($host_file))) {
	print $usage;
	exit 1;
}

# Check for strange option combinations
if (
	(defined($host) and defined($host_file))
	or
	(defined($username) and defined($username_file))
) {
	print "WARNING: You specified a lone username or host AND a file of them.  Continuing anyway...\n";
}

# Check valid mode was given
unless ($mode eq "EXPN" or $mode eq "VRFY" or $mode eq "RCPT") {
	print "ERROR: Invalid mode specified with -M.  Should be VRFY, EXPN or RCPT.  -h for help\n";
	exit 1;
}

# Shovel usernames and host into arrays
if (defined($username_file)) {
	open(FILE, "<$username_file") or die "ERROR: Can't open username file $username_file: $!\n";
	@usernames = map { chomp($_); $_ } <FILE>;
}

if (defined($host_file)) {
	open(FILE, "<$host_file") or die "ERROR: Can't open username file $host_file: $!\n";
	@hosts = map { chomp($_); $_ } <FILE>;
}

if (defined($username)) {
	push @usernames, $username;
}

if (defined($host)) {
	push @hosts, $host;
}

if (defined($host_file) and not @hosts) {
	print "ERROR: Targets file $host_file was empty\n";
	exit 1;
}

if (defined($username_file) and not @usernames) {
	print "ERROR: Username file $username_file was empty\n";
	exit 1;
}


print "\n";
print " ----------------------------------------------------------\n";
print "|                   Scan Information                       |\n";
print " ----------------------------------------------------------\n";
print "\n";
print "Mode ..................... $mode\n";
print "Targets file ............. $host_file\n" if defined($host_file);
print "Usernames file ........... $username_file\n" if defined($username_file);
print "Target count ............. " . scalar(@hosts) . "\n" if @hosts;
print "Username count ........... " . scalar(@usernames) . "\n" if @usernames;
print "Target TCP port .......... $smtp_port\n";
print "Query timeout ............ $query_timeout secs\n";
print "Target domain ............ $domain\n" if defined($domain);
print "\n";
print "######## Scan started at " . scalar(localtime()) . " #########\n";

#connect
my $buffer;
my $s = IO::Socket::INET->new( 	PeerAddr => $host,
PeerPort => $smtp_port,
Proto    => 'tcp'
)or die "Can't connect to $host:$smtp_port: $!\n";
$s->recv($buffer, 10000); # recv banner
$s->send("HELO x\r\n");
$s->recv($buffer, 10000);
$s->send("MAIL FROM:$from_address\r\n");
$s->recv($buffer, 10000);

#make requets
foreach my $username_line (@usernames) {
	my $response;
	my $timed_out = 0;
			eval {
				local $SIG{ALRM} = sub { die "alarm\n" };
				alarm $query_timeout;
					$s->send("RCPT TO:$username_line\r\n");
					$s->recv($buffer, 10000);
				$response .= $buffer;
				#print $response;
				alarm 0;
			};
			my $trace;
			if ($debug) {
				$trace = "[Child $$] $host: $username_line ";
			} else {
				$trace = "$host: $username_line ";
			}

			if ($response and not $timed_out) {

				# Negative result
				if ($response =~ /5\d\d \S+/s) {
					print  $trace . "<no such user>\n";
					#next;

				# Postive result
				} elsif ($response =~ /2\d\d \S+/s) {
					print  $trace . "exists\n";
					#next;

				# Unknown response
				} else {
					$response =~ s/[\n\r]/./g;
					print  $trace . "$response\n";
					#next;
				}
			}

			if ($timed_out) {
				print  $trace . "<timeout>\n";
			} else {
				if (!$response) {
					print  $trace . "<no result>\n";
				}
			}
		

		
}
