/** The core Vue instance controlling the UI */
const vm = new Vue ({
  el: '#vue-instance',
  data () {
    return {
	  id: null,
      cryptWorker: null,
      socket: null,
      originPublicKey: null,
      destinationPublicKey: null,
      messages: [],
      notifications: [],
      currentRoom: null,
      pendingRoom: Math.floor(Math.random() * 1000),
      draft: '',
	  symKey: null,
	  IV: null,
	  hashKey: null
    }
  },
  async created () {
    this.addNotification('Welcome! Generating a new keypair now.')

    // Initialize crypto webworker thread
    this.cryptWorker = new Worker('crypto-worker.js')

    // Generate keypair and join default room
    this.originPublicKey = await this.getWebWorkerResponse('generate-keys')
    this.addNotification(`Keypair Generated - ${this.getKeySnippet(this.originPublicKey)}`)

    // Initialize socketio
    this.socket = io()
    this.setupSocketListeners()
  },
  methods: {
    /** Setup Socket.io event listeners */
    setupSocketListeners () {
      // Automatically join default room on connect
      this.socket.on('connect', () => {
        this.addNotification('Connected To Server.')
        this.joinRoom()
      })

      // Notify user that they have lost the socket connection
      this.socket.on('disconnect', () => this.addNotification('Lost Connection'))

      // Decrypt and display message when received
      this.socket.on('MESSAGE', async (message) => {
		if(message.code == 1){
			const decryptedSALT = await this.getWebWorkerResponse('PKIDecrypt', [message.salt])
			this.iv = await this.getWebWorkerResponse('PKIDecrypt', [message.iv])
			//Generate symmetric keys to decrypt stuffs
			//get 32 bytes key for encryption 256 bit keys
			this.symKey = await this.getWebWorkerResponse(
			  'keyDerive', [ "encryption", decryptedSALT ])
			//get 32 bytes key for hashing / 256 bit keys
			this.hashKey = await this.getWebWorkerResponse(
			  'keyDerive', [ "hash", decryptedSALT ])
			  
		}else if (message.code == 2){
			//decrypt message and hash
			const decryptedMessage = await this.getWebWorkerResponse('PKIDecrypt', [message.text])
			const decryptedSignature = await this.getWebWorkerResponse('PKIDecrypt', [message.signature])
			//calculate hash
			//Non-repudiation and integrity hash
			const hash = await this.getWebWorkerResponse('hmac', [this.hashKey,  await this.getWebWorkerResponse('bytesToStr', [decryptedMessage]) + this.getKeySnippet(this.originPublicKey)])
			const verifySignature = await this.getWebWorkerResponse('verifySign', [hash, this.destinationPublicKey ,decryptedSignature])
			if(verifySignature == 1){
				message.text = await this.getWebWorkerResponse('decrypt', [decryptedMessage, this.symKey, this.iv])
				this.messages.push(message)
			}
		}else{
			this.addNotification(`Message had been deleted. Previous message seems to be modified, please establish a new session.`)
		}
		
     
      })

      // When a user joins the current room, send them your public key
      this.socket.on('NEW_CONNECTION', () => {
        this.addNotification('Another user joined the room.')
        this.sendPublicKey()
      })

      // Broadcast public key when a new room is joined
      this.socket.on('ROOM_JOINED', (newRoom) => {
        this.currentRoom = newRoom
        this.addNotification(`Joined Room - ${this.currentRoom}`)
        this.sendPublicKey()
      })

      // Save public key when received
      this.socket.on('PUBLIC_KEY', async(key, id) => {
        this.addNotification(`Public Key Received - ${key}`)
        this.destinationPublicKey = key
		//generate shared secret
		await this.getWebWorkerResponse('sharedSecret', [null, this.destinationPublicKey])
      })

      // Clear destination public key if other user leaves room
      this.socket.on('user disconnected', () => {
        this.notify(`User Disconnected - ${this.getKeySnippet(this.destinationKey)}`)
        this.destinationPublicKey = null
      })

      // Notify user that the room they are attempting to join is full
      this.socket.on('ROOM_FULL', () => {
        this.addNotification(`Cannot join ${this.pendingRoom}, room is full`)

        // Join a random room as a fallback
        this.pendingRoom = Math.floor(Math.random() * 1000)
        this.joinRoom()
      })

      // Notify room that someone attempted to join
      this.socket.on('INTRUSION_ATTEMPT', () => {
        this.addNotification('A third user attempted to join the room.')
      })
    },

    /** Encrypt and emit the current draft message */
    async sendMessage () {
      // Don't send message if there is nothing to send
      if (!this.draft || this.draft === '') { return }

      // Use immutable.js to avoid unintended side-effects.
      let message = Immutable.Map({
		text: this.draft,
        recipient: this.destinationPublicKey,
        sender: this.originPublicKey,
      })	  
	  

      // Reset the UI input draft text
      this.draft = ''

      // Instantly add (unencrypted) message to local UI
      this.addMessage(message.toObject())
      if (this.destinationPublicKey) {  
		for (var i = 0 ; i < 2; i++){
			var SALT;
			var IV;
			if ( i == 0){
				msg = message.get('text')
				message = message.delete("text")
				//Every round trip message will generate new SALT for PFS
				//Generate SALT for one time use, perfect forward secrecy, every SALT is different / 256 bit randomly generated SALT
				SALT = await this.getWebWorkerResponse( 
				  'generateSalt', [ null ])
				IV = await this.getWebWorkerResponse(
				  'generateIV', [ null ])	
				  
				//Send SALT and IV over to generate  
				const encryptedSALT = await this.getWebWorkerResponse(
				  'PKIEncrypt', [ SALT, this.destinationPublicKey ])
				const encryptedIV = await this.getWebWorkerResponse(
				  'PKIEncrypt', [ IV, this.destinationPublicKey ])	
				  
				const encryptedMsg = message.set('salt', encryptedSALT).set('iv', encryptedIV).set('code', 1)
				this.socket.emit('MESSAGE', encryptedMsg.toObject())
				

			}else{
				//Hybrid cryptography 
				symKey = await this.getWebWorkerResponse(
				  'keyDerive', [ "encryption", SALT ])	
				//get 32 bytes key for hashing / 256 bit keys
				hashKey = await this.getWebWorkerResponse(
				  'keyDerive', [ "hash", SALT ])
 
				const shuffledText = await this.getWebWorkerResponse(
				  'shuffle', [ msg, symKey ])
 
				const deshuffle = await this.getWebWorkerResponse(
				  'DNA_decrypt', [ shuffledText.data, shuffledText.key ])
				console.log(deshuffle)
				
				//Encrypted text with AES OFB E(M) || H(E(M))
				const encryptedText = await this.getWebWorkerResponse(
				  'encrypt', [ msg, symKey, IV ])
				 
				//HASH OF ENCRYPTED TEXT EtM
				const hash = await this.getWebWorkerResponse('hmac', [hashKey, encryptedText + this.getKeySnippet(this.destinationPublicKey)])				  
				
				//Sign				
				const signHash = await this.getWebWorkerResponse(
				  'sign', [ hash ])
				//Encrypt
				const encryptedMessage = await this.getWebWorkerResponse(
				  'PKIEncrypt', [ await this.getWebWorkerResponse('strToBytes', [encryptedText]), this.destinationPublicKey ])		
				const encryptedSignHash = await this.getWebWorkerResponse(
				  'PKIEncrypt', [ signHash, this.destinationPublicKey ])  
				  
				const newMsg = message.set('text', encryptedMessage).set('signature', encryptedSignHash).set('code', 2)  
				setTimeout(() => { this.socket.emit('MESSAGE', newMsg.toObject()) }, 500)
				

				
			}
		}
      }
    },

    /** Join the specified chatroom */
    joinRoom () {
      if (this.pendingRoom !== this.currentRoom && this.originPublicKey) {
        this.addNotification(`Connecting to Room - ${this.pendingRoom}`)

        // Reset room state variables
        this.messages = []
        this.destinationPublicKey = null
        // Emit room join request.
        this.socket.emit('JOIN', this.pendingRoom)
      }
    },

    /** Add message to UI, and scroll the view to display the new message. */
    addMessage (message) {
      this.messages.push(message)
      this.autoscroll(this.$refs.chatContainer)
    },

    /** Append a notification message in the UI */
    addNotification (message) {
      const timestamp = new Date().toLocaleTimeString()
      this.notifications.push({ message, timestamp })
      this.autoscroll(this.$refs.notificationContainer)
    },

    /** Post a message to the webworker, and return a promise that will resolve with the response.  */
    getWebWorkerResponse (messageType, messagePayload) {
      return new Promise((resolve, reject) => {
        // Generate a random message id to identify the corresponding event callback
        const messageId = Math.floor(Math.random() * 100000)

        // Post the message to the webworker
        this.cryptWorker.postMessage([messageType, messageId].concat(messagePayload))

        // Create a handler for the webworker message event
        const handler = function (e) {
          // Only handle messages with the matching message id
          if (e.data[0] === messageId) {
            // Remove the event listener once the listener has been called.
            e.currentTarget.removeEventListener(e.type, handler)

            // Resolve the promise with the message payload.
            resolve(e.data[1])
          }
        }

        // Assign the handler to the webworker 'message' event.
        this.cryptWorker.addEventListener('message', handler)
      })
    },

    /** Emit the public key to all users in the chatroom */
    sendPublicKey () {
      if (this.originPublicKey) {
        this.socket.emit('PUBLIC_KEY', this.originPublicKey)
      }
    },
	
    /** Get key snippet for display purposes */
    getKeySnippet (key) {
      return key.slice(10, 16)
    },

    /** Autoscoll DOM element to bottom */
    autoscroll (element) {
      if (element) { element.scrollTop = element.scrollHeight }
    }
  }
})
