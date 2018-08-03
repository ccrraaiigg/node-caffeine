// caffeine-node is a NodeJS module providing SSH and WebDAV services
// for in-browser Caffeine sessions.
//
// Author: Craig Latta <craig@blackpagedigital.com>

const width = 70

var hostPrivateKey = '/etc/letsencrypt/live/frankfurt.demo.blackpagedigital.com/privkey.pem',
    hostCertificate = '/etc/letsencrypt/live/frankfurt.demo.blackpagedigital.com/fullchain.pem',
    hostname = 'frankfurt.demo.blackpagedigital.com',
    clients = [],
    operatorPort = 8100,
    nextSSHPort = operatorPort + 1,
    fs = require('fs'),
    ws = require('ws'),
    https = require('https'),
    crypto = require('crypto'),
    buffersEqual = require('buffer-equal-constant-time'),
    uuid = require('uuid/v1'),
    ssh2 = require('ssh2'),
    utils = ssh2.utils,
    confirm = require('prompt-confirm'),
    childProcess = require('child_process'),
    wrap = require('word-wrap'),
    userPublicKey,
    lflfcr = '\u000A\u000A\u000D'

function shellPrompt(client) {
    return '"'}

function serveHTTPS(callback, port) {
    return https.createServer(
	{
	    key: fs.readFileSync(hostPrivateKey),
	    cert: fs.readFileSync(hostCertificate)
	},
	callback).listen(port)}

function logToHTTPResponse(response, string) {
    response.writeHead(500)
    response.end(string + '\n')
    console.log(string)}

function logToWebsocket(websocket, string) {
    websocket.send(string)
    console.log(string)}

function addClient(port) {
    var client = new Object
    clients.push(client)
    client.webserverTarget = null
    client.sshServerTarget = null
    client.webserverResponses = []
    client.nextWebserverResponseIndex = 0
    client.sshCommands = []
    client.input = []
    client.currentFolder = '/'
    client.sshCommandIndex = null
    client.fragment = ''
    client.credential = uuid()
    client.sshPort = port
    client.sshFromCaffeinePort = port + 1
    client.httpPort = port + 2
    client.httpFromCaffeinePort = port + 3
    client.connectionExpression = new Buffer('[:connectionDialog | connectionDialog connectToPorts: #(' + client.sshFromCaffeinePort + ' ' + client.httpFromCaffeinePort + ') atHostNamed: \'' + hostname + '\' withCredential: \'' + client.credential + '\']').toString('base64')

    // Start a SSH server with which a remote shell speaks.
    new ssh2.Server(
	{hostKeys: [fs.readFileSync('host_rsa')]},
	(relayClient) => {
	    relayClient.on(
		'authentication',
		(context) => {
		    if (context.method === 'publickey'
			&& context.key.algo === userPublicKey.fulltype
			&& buffersEqual(context.key.data, userPublicKey.public)) {
			if (context.signature) {
			    var verifier = crypto.createVerify(context.sigAlgo)

			    verifier.update(context.blob)
			    
			    if (verifier.verify(userPublicKey.publicOrig, context.signature))
				context.accept()
			    else context.reject()}
			else {
			    // If no signature present, that means the
			    // ssh client is just checking the validity of the
			    // given public key.
			    context.accept()}}
		    else context.reject()}
	    ).on(
		'ready',
		() => {
		    console.log('connected ssh client')

		    relayClient.on(
			'session',
			(accept, reject) => {
			    var session = accept()

			    session.once(
				'pty',
				(accept, reject, info) => {accept()}
			    ).once(
				'shell',
				(accept, reject, info) => {
				    client.sshStream = accept(),
				    client.input = []

				    client.sshStream.write(lflfcr + wrap('Welcome to Caffeine. Type control-d to exit, \'help\' for help.', {width: width}))

				    client.sshStream.write(lflfcr + shellPrompt(client))
				    client.sshStream.on(
					'data',
					(chunk) => {
					    switch (chunk[chunk.length - 1]) {
					    case 4:
						// control-d: show command completions
						var fragment = Buffer.concat(client.input).toString()
						if (fragment.length > 0) {
						    client.fragment = fragment
						    client.sshServerTarget.send(JSON.stringify({
							partial: true,
							content: fragment}))}
						else client.sshStream.end()
						break
					    case 8:
						// backspace: ignore
						break
					    case 9:
						// tab: complete command
						var fragment = Buffer.concat(client.input).toString()
						if (fragment.length > 0) {
						    client.fragment = fragment
						    client.sshServerTarget.send(JSON.stringify({
							partial: true,
							content: fragment}))}
						break
					    case 11: // ignore
						break
					    case 12:
						// control-l: refresh
						client.sshStream.write('\u001b[2J\u001b[0;0H' + shellPrompt(client) + Buffer.concat(client.input).toString())
						break
					    case 13:
						// enter: run command
						debugger
						var command = Buffer.concat(client.input).toString()
						client.sshStream.write('\u000D\u001b[0K' + wrap('You say '))
						if (command.length > 0) client.sshStream.write('"' + command + '"')
						else client.sshStream.write('nothing.')
						client.sshStream.write(lflfcr)
						client.sshCommands.push(command)
						client.sshCommandIndex = client.sshCommands.length - 1

						switch (command) {
						case 'exit':
						    client.sshStream.end()
						    break
						case '':
						    client.sshStream.write(wrap('Time passes.') + lflfcr + shellPrompt(client))
						    break
						default:
						    client.sshServerTarget.send(JSON.stringify({
							partial: false,
							content: command}))}

						client.input = []
						break
					    case 16:
						// control-p: edit previous command
						if (client.sshCommandIndex >= 0) {
						    var remainder = client.sshCommands[sshCommandIndex]
						    client.sshStream.write('\u000D\u001b[0K' + shellPrompt(client) + remainder)
						    client.sshCommandIndex = client.sshCommandIndex - 1
						    client.input = []
						    client.input.push(Buffer.from(remainder))}
						break
					    case 23:
						// control-w: delete previous word
						if (client.input.length > 0) {
						    client.sshStream.write('\u000D\u001b[0K' + shellPrompt(client))
						    var reverse = function (s) { return s.split('').reverse().join('') },
							remainder = client.input[client.input.length - 1].toString().split(/\s(?=\S+$)/).reverse()
						    if (remainder.length === 2) remainder = remainder[1]
						    else remainder = ''
						    client.sshStream.write(remainder)
						    client.input = []
						    client.input.push(Buffer.from(remainder))}
						break
					    case 127:
						// delete: delete previous character
						client.sshStream.write('\u000D\u001b[0K' + shellPrompt(client))
						var remainder = Buffer.concat(client.input).toString().slice(0, -1)
						client.sshStream.write(remainder)
						client.input = []
						client.input.push(Buffer.from(remainder))
						break
					    default:
						// collect printable characters
						if (chunk[chunk.length - 1] >= 32) {
						    client.input.push(chunk)
						    client.sshStream.write(chunk.toString())}}})})}
		    ).on(
			'end',
			() => {
			    console.log('disconnected SSH client')})})}
    ).listen(
	client.sshPort,
	'172.31.21.123',
	() => {console.log('SSH server listening on port ' + client.sshPort + '.')})

    // Start web relay server.
    
    client.httpToCaffeine = serveHTTPS(
	(request, response) => {
	    if (client.webserverTarget) {
		var body = [],
		    payload

		request.on(
		    'data',
		    (chunk) => {body.push(chunk)}
		).on(
		    'end',
		    () => {
			body = Buffer.concat(body).toString()
			response.request = request
			client.webserverResponses[client.nextWebserverResponseIndex] = response
			payload = JSON.stringify({
			    requestNumber: nextWebserverResponseIndex,
			    headers: request.headers,
			    method: request.method,
			    url: request.url,
			    body: body})
			client.nextWebserverResponseIndex = client.nextWebserverResponseIndex + 1
			// console.log('\nincoming HTTP: ' + payload)
			client.webserverTarget.send(payload)})}
	    else logToHTTPResponse(response, 'HTTP server not connected yet')},
	client.httpPort)

    client.httpFromCaffeine = new ws.Server({
	server: serveHTTPS(
	    (request, response) => {
		console.log('web relay server ignoring non-websocket request')},
	    client.httpFromCaffeinePort)}).on(
		'connection',
		(websocket, request) => {
		    console.log('connected webserver')
		    client.webserverTarget = websocket
		    client.webserverTarget.on(
			'message',
			(message) => {
			    var frame = JSON.parse(message),
				response = client.webserverResponses[frame.requestNumber]
		    
			    if (response != null) {
				if (frame.credential != credential) {
				    client.webserverTarget.close()
				    client.webserverTarget = null}
				else {
				    // console.log('\noutgoing HTTP: ' + message)
				    for (var property in frame.headers) {
					response.setHeader(property, frame.headers[property])}
				    response.statusCode = frame.status
				    if (frame.body != null) response.end(frame.body)
				    else response.end()}

				client.webserverResponses[frame.requestNumber] = null}}
		    ).on(
			'close',
			(event) => {
			    client.webserverTarget = null
			    console.log('disconnected webserver')})})

    // Start SSH relay server.

    client.sshFromCaffeine = new ws.Server({
	server: serveHTTPS(
	    (request, response) => {
		console.log('ssh relay server ignoring non-websocket request')},
	    client.sshFromCaffeinePort)}).on(
		'connection',
		(websocket, request) => {
		    if (!client.sshServerTarget) {
			console.log('connected ssh server')
			client.sshServerTarget = websocket
			client.sshServerTarget.on(
			    'message',
			    (message) => {
				var frame = JSON.parse(message),
				    response = frame.response

				if (!(frame.credential == client.credential)) {
				    client.sshServerTarget.close()
				    client.sshServerTarget = null}
				else {
				    if (frame.partial) {
					if (frame.choose) {

					    client.sshStream.write('\u000D\u001b[0K' + shellPrompt(client) + response)
					    client.input = []
					    client.input.push(Buffer.from(response, 'utf8'))}
					else {
					    client.sshStream.write('...' + lflfcr + wrap(response, {width: width}) + lflfcr + shellPrompt(client) + client.fragment)
					    client.input = []
					    client.input.push(Buffer.from(client.fragment, 'utf8'))}}
				    else {
					currentFolder = frame.currentFolder
					client.sshStream.write(wrap(response, {width: width}) + lflfcr + shellPrompt(client))}}}
			).on(
			    'close',
			    (event) => {
				client.sshServerTarget = null
				console.log('disconnected ssh server')})}
		    else logToWebsocket(websocket, 'ssh server already connected')})

    return client}

var operator = new ws.Server({
    server: serveHTTPS(
	(request, response) => {console.log('operator server ingoring non-websocket request')},
	operatorPort)})

operator.on(
    'connection',
    (websocket, request) => {
	console.log('connected to operator')
	websocket.on(
	    'message',
	    (message) => {
		var client = addClient(nextSSHPort)

		websocket.send(JSON.stringify({
		    sshPort: client.sshPort,
		    sshFromCaffeinePort: client.sshFromCaffeinePort,
		    httpPort: client.httpPort,
		    httpFromCaffeinePort: client.httpFromCaffeinePort,
		    credential: client.credential}))
		websocket.close()
		nextSSHPort = nextSSHPort + 4})})

// Ensure there's a user key pair.

try{userPublicKey = utils.genPublicKey(utils.parseKey(fs.readFileSync('user.pub')))}
catch(exception) {}

if (!userPublicKey) {
    var prompt = new confirm('There is no public key configured. Shall I create a key pair?')
    prompt.ask(
	(answer) => {
	    if (answer) {
		var generateKeys = childProcess.spawn(
		    'ssh-keygen',
		    ['-t', 'rsa', '-N', '', '-f', 'user'])

		generateKeys.on(
		    'error',
		    (error) => {console.log('ssh-keygen closed with error ' + error)})
		
		generateKeys.on(
		    'close',
		    (code) => {
			if (code == 0) {
			    userPublicKey = utils.genPublicKey(utils.parseKey(fs.readFileSync('user.pub')))}
			else
			    console.log('ssh-keygen closed with code ' + code)})}
	    else process.exitCode = 1})}
