import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def b64(msg):
    return base64.encodebytes(msg).decode("utf-8").strip()

def unb64(msg):
    return base64.decodebytes(msg.encode("utf-8"))

def hkdf(inp, length, salt=b''):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=b'', backend=default_backend()).derive(inp)

def AESEncrypt(key, iv, data):
	cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(data) + encryptor.finalize()
	return ciphertext

def AESDecrypt(key, iv, ciphertext):
	cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
	decryptor = cipher.decryptor()
	plaintext = decryptor.update(ciphertext) #+ decryptor.finalize_with_tag(None) ## GCM auth pending
	return plaintext

def getPublicKeyFingerprint(public_key):
	return hashlib.md5(public_key._raw_public_bytes()).hexdigest()	

KDS = {} ### Declaring it global as this will be a public service maintained by the provider

class SymmRatchet(object):
	def __init__(self, key, ratchet_name):
		self.chain_key = key
		self.chain_index = 0

	def nextKey(self, inp=b''):
		output = hkdf(self.chain_key + inp , 80)#, self.salt)
		self.chain_key = output[:32]
		message_key, iv = output[32:64], output[64:]
		self.chain_index += 1
		return message_key, iv


class User():
	def __init__(self, name):
		self.name = name
		self.IK = X448PrivateKey.generate()
		self.EK = X448PrivateKey.generate()
		self.OPK1 = X448PrivateKey.generate() ### 100 OPKs in one go. Utilize internal keystore for this
		self.SK = None
		self.DHRatchet = X448PrivateKey.generate()
		self.RootRatchet = None
		self.AVRatchetKeyMaterial = None
		self.AVRatchet = None
		self.SendRatchet = None
		self.RecvRatchet = None
		self.RecepientPubKey = None
		self.FriendDHKey= None
		self.SendCounter = 0
		self.ReceiveCounter = 0
		self.FlipRatchetDirection =0
		KDS[name] = {"IK": self.IK.public_key(), "EK": self.EK.public_key()}#, "OPK1": self.OPK1.public_key()}
		self.internal_keystore = {getPublicKeyFingerprint(self.IK.public_key()): self.IK, getPublicKeyFingerprint(self.EK.public_key()): self.EK, getPublicKeyFingerprint(self.OPK1.public_key()): self.OPK1}

	def logger(self, log):
		print("["+self.name+"] ", log)

	def DHKX(self, username, EP=None):
		### Lookup own private key againts fingerprint
		sender_identity_key = self.IK
		if EP != None:
			sender_ephemeral_key = self.internal_keystore[EP]
		else:
			sender_ephemeral_key = self.EK

		recepient_identity_pubkey = KDS[username]["IK"] ## Fetched from KDS
		recepient_opk_pubkey = KDS[username]["EK"] ## Fetched from KDS
		del(KDS[username]["EK"]) ## Discarding EK after use
		self.RecepientPubKey = recepient_opk_pubkey
		dh1 = sender_identity_key.exchange(recepient_opk_pubkey)
		dh2 = sender_ephemeral_key.exchange(recepient_identity_pubkey)
		dh3 = sender_ephemeral_key.exchange(recepient_opk_pubkey)
		if self.FlipRatchetDirection == 1:
			sk = hkdf(dh2 + dh1 + dh3, 32) ### have to debug DHRatchet
		else:
			sk = hkdf(dh1 + dh2 + dh3, 32)
		self.SK = sk

	def initRatchets(self):
		self.RootRatchet = SymmRatchet(self.SK, b"RootRatchet")
		# self.AVRatchet = SymmRatchet(self.SK, b"AudioVideoRatchet")
		if self.FlipRatchetDirection != 1:
			self.SendRatchet = SymmRatchet(self.RootRatchet.nextKey()[0], b"MessageRatchet")
			self.RecvRatchet = SymmRatchet(self.RootRatchet.nextKey()[0], b"MessageRatchet")
		else:
			self.RecvRatchet = SymmRatchet(self.RootRatchet.nextKey()[0], b"MessageRatchet")
			self.SendRatchet = SymmRatchet(self.RootRatchet.nextKey()[0], b"MessageRatchet")
		return

	def preDHRatchet(self):
		self.SK = self.DHRatchet.exchange(self.FriendDHKey)
		self.initRatchets()

	def DHRatchetNext(self):
		self.DHRatchet = X448PrivateKey.generate()
		self.SK = self.DHRatchet.exchange(self.FriendDHKey)
		self.initRatchets()
		return

	def sendMessage(self, recepient, message):
		if self.ReceiveCounter == 0:
			self.SendCounter += 1
			return self.sendPreKeyMessage(message, recepient)
		if self.FriendDHKey:
			self.logger("Ticking DHRatchet")
			self.DHRatchetNext()
		key, iv = self.SendRatchet.nextKey()
		ciphertext = b64(AESEncrypt(key, iv, message.encode('utf-8')))
		## With NextDH so both ratchets tick
		payload = {"sender": self.name, "messageCipher": ciphertext, "NextDHKey": self.DHRatchet.public_key(), "message_counter": "for message ordering", "ChainIndex": self.SendRatchet.chain_index}
		## without NextDH so only symmetric ratchets tick
		#payload = {"sender": self.name, "messageCipher": ciphertext, "message_counter": "for message ordering", "Chain Index": self.SendRatchet.chain_index}
		self.SendCounter += 1
		return payload

	def receiveMessage(self, sender, payload):
		if self.ReceiveCounter == 0 and self.SendCounter == 0:
			self.ReceiveCounter += 1
			return self.receivePreKeyMessage(payload, sender)
		if "NextDHKey" in payload.keys(): 
			if self.FriendDHKey == None or payload["NextDHKey"]._raw_public_bytes() != self.FriendDHKey._raw_public_bytes():
				self.FriendDHKey = payload["NextDHKey"]
				self.preDHRatchet()
		ciphertext = payload["messageCipher"]
		key, iv = self.RecvRatchet.nextKey()
		message = AESDecrypt(key, iv, unb64(ciphertext))
		self.logger(payload["sender"] + " sent a message : " + str(message))
		self.ReceiveCounter += 1
		return message

	def sendPreKeyMessage(self, message, recepient):
		if self.SK == None:
			self.DHKX(recepient)
			self.initRatchets()
		key, iv = self.SendRatchet.nextKey()
		ciphertext = b64(AESEncrypt(key, iv, message.encode('utf-8')))
		## With NextDH so both ratchets tick
		payload = {"sender": self.name, "messageCipher": ciphertext, "NextDHKey": self.DHRatchet.public_key(), "senderPubKey": self.EK.public_key() ,"recepientPubKeyFingerprint": getPublicKeyFingerprint(self.RecepientPubKey), "ChainIndex": self.SendRatchet.chain_index}
		## without NextDH so only symmetric ratchets tick
		# payload = {"sender": self.name, "messageCipher": ciphertext, "senderPubKey": self.EK.public_key() ,"recepientPubKeyFingerprint": getPublicKeyFingerprint(self.RecepientPubKey), "ChainIndex": self.SendRatchet.chain_index}
		### Sending AVRatchet KeyMaterial
		if self.AVRatchetKeyMaterial == None:
			self.AVRatchetKeyMaterial = os.urandom(32)
		payload["AVRatchetKeyMaterial"] = self.AVRatchetKeyMaterial
		if self.AVRatchet == None:
			self.AVRatchet = SymmRatchet(self.AVRatchetKeyMaterial, b"AVRatchet")
		return payload

	def receivePreKeyMessage(self, payload, sender):
		if self.SK == None:
			self.FlipRatchetDirection = 1
			self.DHKX(sender, payload["recepientPubKeyFingerprint"])
			self.initRatchets()
		ciphertext = payload["messageCipher"]
		key, iv = self.RecvRatchet.nextKey()
		message = AESDecrypt(key, iv, unb64(ciphertext))
		self.logger(payload["sender"] + " sent a message : " + str(message))
		if "NextDHKey" in payload.keys():
			if self.FriendDHKey == None or payload["NextDHKey"]._raw_public_bytes() != self.FriendDHKey._raw_public_bytes():
				self.FriendDHKey = payload["NextDHKey"]
		if "AVRatchetKeyMaterial" in payload.keys() and self.AVRatchetKeyMaterial == None:
			self.AVRatchet = SymmRatchet(payload["AVRatchetKeyMaterial"], b"AVRatchet")
		return


## User is registered
alice = User("alice")
bob = User("bob")


payload1 = alice.sendMessage("bob", "Hey bob!")
payload2 = alice.sendMessage("bob", "How are you doing?")
bob.receiveMessage("alice", payload1)
bob.receiveMessage("alice", payload2)

payload = bob.sendMessage("alice", "Hi Alice! I'm Good.")
payload2 = bob.sendMessage("alice","What about you?")
alice.receiveMessage("bob", payload)
alice.receiveMessage("bob", payload2)

payload = alice.sendMessage("bob", "Good")
bob.receiveMessage("alice", payload)
payload = alice.sendMessage("bob", "Clock work isn't on time")
bob.receiveMessage("alice", payload)

payload = bob.sendMessage("alice", "How about the numbers?")
alice.receiveMessage("bob", payload)

payload = alice.sendMessage("bob", "The numbers seem fine")
bob.receiveMessage("alice", payload)

### Post Notes
### An encrypted channel is a single instance of double ratchet between two users, a group conversation with 6 members will require the sender to open 6 encrypted channels and send one message via all channels unless media message
### If any message is above 2 MB we send it using symmetric AVRatchet, for eventual break-in recovery we can keep a counter of AV messages and in DHRatchet turn AVRatchet only after every (n)th message
### KDS needs to be a class instance that's globally accessible
### We will be using client-side-fanout for group conversations instead of server side
### Ideally insted of maintianing counters we can utilize chain index to figure out if the message is prekey or not