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
      draft: ''
    }
  },
  async created () {
    this.addNotification('Welcome! Generating a new keypair now.')

    // Initialize crypto webworker thread
    this.cryptWorker = new Worker('crypto-worker.js')

    // Generate keypair and join default room
    this.originPublicKey = await this.getWebWorkerResponse('generate-keys')
	this.id = this.getKeySnippet(this.originPublicKey)
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

        // Only decrypt messages that were encrypted with the user's public key

        if (message.recipient === this.originPublicKey) {
		  //Decrypt Key and IV with ECC
		  console.log(message)
		  const symmetricKey = await this.getWebWorkerResponse('PKIDecrypt', [message.derivedKey])
		  const decryptedIV = await this.getWebWorkerResponse('PKIDecrypt', [message.IV])
		  const decryptedHash = await this.getWebWorkerResponse('PKIDecrypt', [message.hashValue])

		  
		  //Decrypt Signatures
		  const decryptedSignText = await this.getWebWorkerResponse('PKIDecrypt', [message.Sign.EncryptedSignText])
		  const decryptedSignHash = await this.getWebWorkerResponse('PKIDecrypt', [message.Sign.EncryptedSignHash])
		  const decryptedSignIV = await this.getWebWorkerResponse('PKIDecrypt', [message.Sign.EncryptedSignIV])
		  const decryptedSignKey = await this.getWebWorkerResponse('PKIDecrypt', [message.Sign.EncryptedSignKey])
		  


		  //verify Signature
		  const verifyHash = await this.getWebWorkerResponse('verifySign', [decryptedHash, this.destinationPublicKey, decryptedSignHash])
		  const verifyIV = await this.getWebWorkerResponse('verifySign', [decryptedIV, this.destinationPublicKey, decryptedSignIV])
		  const verifyKey = await this.getWebWorkerResponse('verifySign', [symmetricKey, this.destinationPublicKey, decryptedSignKey])
		
		//Verify if the Hash, IV and KEY is sent by who it claims to be
		if (verifyHash == 1 && verifyKey == 1 && verifyIV == 1){
			//get 32 bytes key for hashing				
			const hashKey = await this.getWebWorkerResponse(
			  'keyDerive', [ "hashKey" ])
			//calculate Hash of message
			const hash = await this.getWebWorkerResponse('hmac', [hashKey, message.text])
			const hashed = await this.getWebWorkerResponse('bytesToStr', [hash])
			//Hash String of decryptedHash
			const hashString = await this.getWebWorkerResponse(
			  'bytesToStr', [ decryptedHash ])			
			if(hashed == hashString){			
				//check if the message had been modified and the message is sent by who it is deem to be
				const verifyText = await this.getWebWorkerResponse('verifySign', [message.text, this.destinationPublicKey, decryptedSignText])
				if(verifyText == 1){
					// Decrypt the message text in the webworker thread
					message.text = await this.getWebWorkerResponse('decrypt', [message.text, symmetricKey, decryptedIV])
					this.messages.push(message)
				}	
				else{
					this.addNotification(`Message had been deleted. Previous message seems to be modified, please establish a new session.`)
				}
			}else{
				this.addNotification(`Message had been deleted. Previous message seems to be modified, please establish a new session.`)
			}
			
		}
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
      this.socket.on('PUBLIC_KEY', async(key) => {
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
		hashValue: null,
		derivedKey: null,
		IV: null,
		Sign: null
      })

      // Reset the UI input draft text
      this.draft = ''

      // Instantly add (unencrypted) message to local UI
      this.addMessage(message.toObject())

      if (this.destinationPublicKey) {
		  
		  /*Step 1 Generate Keys */
		//get 32 bytes key for encryption
		const derivedKey = await this.getWebWorkerResponse(
          'keyDerive', [ "encryption" ])
		//get 16 bytes IV for encryption
		const IV = await this.getWebWorkerResponse(
          'generateIV', [ "encryption" ])		
		//get 32 bytes key for hashing
		const hashKey = await this.getWebWorkerResponse(
          'keyDerive', [ "hashKey" ])
		  

		// Symmetric AES OFB (ENCRYT-THEN-HASH)
        const encryptedText = await this.getWebWorkerResponse(
          'encrypt', [ message.get('text'), derivedKey, IV ])  
		const hash = await this.getWebWorkerResponse('hmac', [hashKey, encryptedText])		//Hash the message
		//convert Bytes to string the keys   
		
		
		//Signature
		const SignText = await this.getWebWorkerResponse(
          'sign', [ encryptedText])
		const SignHash = await this.getWebWorkerResponse(
          'sign', [ hash ])
		const SignKey = await this.getWebWorkerResponse(
          'sign', [ derivedKey])
		const SignIV = await this.getWebWorkerResponse(
          'sign', [ IV ])		  
		  
		/*Asymmetric*/
        const EncryptedKey = await this.getWebWorkerResponse(
          'PKIEncrypt', [ derivedKey, this.destinationPublicKey ])	
        const EncryptedIV = await this.getWebWorkerResponse(
          'PKIEncrypt', [ IV, this.destinationPublicKey ])	
		const EncryptedHash = await this.getWebWorkerResponse(
          'PKIEncrypt', [ hash, this.destinationPublicKey ])
		//Encrypt Signatures
		const EncryptedSignText = await this.getWebWorkerResponse(
          'PKIEncrypt', [ SignText, this.destinationPublicKey ])  
		const EncryptedSignHash = await this.getWebWorkerResponse(
          'PKIEncrypt', [ SignHash, this.destinationPublicKey ]) 
		const EncryptedSignKey = await this.getWebWorkerResponse(
          'PKIEncrypt', [ SignKey, this.destinationPublicKey ]) 
		const EncryptedSignIV = await this.getWebWorkerResponse(
          'PKIEncrypt', [SignIV, this.destinationPublicKey ]) 		  
		
		
		const encryptedMsg = message.set('text', encryptedText).set('derivedKey', EncryptedKey).set('IV', EncryptedIV).set('hashValue', EncryptedHash).set('Sign', {EncryptedSignText, EncryptedSignHash,EncryptedSignKey,EncryptedSignIV})
		console.log(encryptedMsg.toObject())
		
        // Emit the encrypted message
        this.socket.emit('MESSAGE', encryptedMsg.toObject())
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
