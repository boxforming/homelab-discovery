#!/usr/bin/env bats

TEST_USERNAME=forremote
CERT_PATH=$HOME/$TEST_USERNAME.crt.pem
PUB_KEY_PATH=$HOME/$TEST_USERNAME.key.pub
SERVER_PID=

function setup() {
	source scripts/boxforming.sh
}

@test "Should be able to generate certificate" {
	run new_client_auth_cert $TEST_USERNAME
	[ -f $HOME/$TEST_USERNAME.crt.pem ]
	[ -f $HOME/$TEST_USERNAME.key.pem ]
	[ -f $HOME/$TEST_USERNAME.key.pub ]
}

@test "Should be able to parse certificate" {

    local SAN_OFFSET

    SAN_OFFSET="$(
        openssl asn1parse -in "$CERT_PATH" |
        grep -A 1 ':X509v3 Subject Alternative Name' |
        tail -n 1 |
        cut -d ':' -f 1
    )"

    echo "CERT_PATH=$CERT_PATH" >&2
    echo "SAN offset=$SAN_OFFSET" >&2
    
	run openssl asn1parse -in "$CERT_PATH" -strparse "$SAN_OFFSET"

    echo "OUTPUT=${output}" >&2
	
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Microsoft Universal Principal Name" ]]
	[[ "$output" =~ "${TEST_USERNAME}@localhost" ]]
}

@test "Should be able to start cert share web server" {
	STORE_PID=1
	start_cert_share_server $TEST_USERNAME &
	echo $! > "$BATS_TEST_TMPDIR/server.pid"

    local is_server_running=false

    for i in {1..20}; do
        if curl -fs http://127.0.0.1:8000/cert.pem >/dev/null; then
            is_server_running=true
            break
        fi
        sleep 0.25
    done

    [ "$is_server_running" = true ]
	
	run curl -O http://127.0.0.1:8000/cert.pem
	[ "$status" -eq 0 ]
	run curl -O http://127.0.0.1:8000/key.pub
	[ "$status" -eq 0 ]
	cmp -s "cert.pem" "$CERT_PATH"
	cmp -s "key.pub" "$PUB_KEY_PATH"
}


@test "Finalize" {
	rm $HOME/$TEST_USERNAME.crt.pem
	rm $HOME/$TEST_USERNAME.key.pem
	rm $HOME/$TEST_USERNAME.key.pub

	skip
}

function teardown() {

    if [ -f "$BATS_TEST_TMPDIR/server.pid" ]; then
        kill "$(cat "$BATS_TEST_TMPDIR/server.pid")" 2>/dev/null || true
        rm -f "$BATS_TEST_TMPDIR/server.pid"
    fi
    
	# pkill -P $$
	#kill -SIGTERM -- "-$SERVER_PID"
	# kill $(ps -o pid= --ppid $$)
	#echo $SERVER_PID >&3
	#if [ "x$SERVER_PID" != "x" ] ; then
	#	echo "killing" >&3
	#	kill $SERVER_PID
	#fi
}
