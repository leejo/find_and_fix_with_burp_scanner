#!perl

use strict;
use warnings;

use Test::Most;
use Test::Mojo;
use Try::Tiny::SmartCatch;
use FindBin;

require "$FindBin::Bin/../lil_app.broken_top_ten";

my $t = Test::Mojo->new;

subtest 'home and login' => sub {
	$t->get_ok( '/' )
		->status_is( 200 )
		->content_like( qr/Login/ )
	;
};

subtest 'OWASP 1. SQL Injection' => sub {

	$t->ua->inactivity_timeout( 1 );

	try sub {

		$SIG{ALRM} = sub { die "Inactivity timeout" };
		alarm( 1 );

		$t->post_ok( '/login' => form => {
			# we inject a sleep attack as syntax errors, etc, can be masked whereas
			# a timing attack we can easily timout to confirm it worked
			username => "' UNION SELECT 1,1,1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))));"
		} )
			->status_is( 200 )
			->content_unlike( qr/incorrect password/ )
		;
	},
	catch_default sub {
		alarm( 0 );
		fail( "Inactivity timeout = SQL injection" );
	};
};

subtest 'OWASP 2. Broken Authentication' => sub {

	$t->post_ok( '/login' => form => {
		username => "lee",
		password => "bad"
	} )
		->status_is( 200 )
		->content_unlike( qr/incorrect password/ )
	;
};

subtest 'OWASP 3. Sensitive Data Exposure' => sub {

	$t->post_ok( '/login' => form => { username => "\\'\\;show tables'" } )
		->status_is( 200 )
		->content_unlike( qr/DBD::/ )
		->content_unlike( qr/unrecognized token/ )
	;

	$t->get_ok( '/exception' )
		->status_is( 200 )
		->content_unlike( qr/Template paths:/ )
	;
};

subtest 'OWASP 4. XML External Entities' => sub {

	$t->post_ok( '/soap' => { 'Content-Type' => 'application/xml' } => '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck> 
'
	)
		->status_is( 200 )
		->content_unlike( qr/root:/ )
	;
};

subtest 'OWASP 5. Broken Access Control' => sub {

	$t->ua->max_redirects( 1 );
	$t->post_ok( '/login' => form => {
		username => 'lee',
		password => 'letmein',
	} )
		->status_is( 200 )
	;

	$t->get_ok( '/mobile/lee' )
		->status_is( 200 )
		->content_is( '0794270000' )
	;

	$t->get_ok( '/mobile/laurent' )
		->status_is( 404 )
	;
};

subtest 'OWASP 7. XSS' => sub {

	$t->post_ok( '/login' => form => {
		username => '<script>alert("Boo!");</script>',
		password => 'fooooo',
	} )
		->status_is( 200 )
		->content_unlike( qr{<script>alert\("Boo!"\);</script>} )
	;

};

done_testing();
