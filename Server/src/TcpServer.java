import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64.Decoder;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class TcpServer {
	public static final String RSA_ALGORITHM = "RSA";
	public static final String HASH_ALGORITHM = "SHA-256";
	public static final String SIGN_ALGORITHM = "SHA256withRSA";
	
	public static final String ASYMMETRIC_ENCRYPTION = "RSA/ECB/PKCS1Padding";
	public static final String SYMMETRIC_ENCRYPTION = "AES/CBC/PKCS5Padding";
	
	// Port number server is listening on.
	public static final int PORTNUMBER=12061;
	// Array of server side client sockets for each client.
	private ArrayList<ClientHandlerThread> clients = new ArrayList<ClientHandlerThread>();
	// Socket on server listening for clients.
	private ServerSocket listener = null;
	// Boolean for while loop, to exit.
	private volatile boolean bExit;
	// Keeping track of number of sockets connected to the server.
	private int clientCount = 0;
	
	private PrivateKey serverPvtKey;
    private String KeyID;
    private HashMap<String, String> publicKeys;
	
	public static void main (String[] args) {
		// Create a server to listen on a specific port and starts listening for new connections.
		TcpServer chatServer = new TcpServer(PORTNUMBER);
		chatServer.run();
	}
		
	private TcpServer(int portNo) {
		try {
			// Load private key from keyring.
			File keyring = new File("../ServerPrivate.txt");
			
			BufferedReader brPrivate = new BufferedReader(new FileReader(keyring));
			String privateKeyInfo = brPrivate.readLine();
			brPrivate.close();
			
			int iSplitPvtIndex = privateKeyInfo.indexOf("||");
			
			KeyID = privateKeyInfo.substring(0, iSplitPvtIndex);
			String sPrivateKey = privateKeyInfo.substring(iSplitPvtIndex+2);
			
			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
			
			Base64.Decoder decoder = Base64.getDecoder();
			
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decoder.decode(sPrivateKey));
			serverPvtKey = keyFactory.generatePrivate(privateKeySpec);
			System.out.println("Loaded server's private key with Key ID: "+KeyID+".");
			
			// Load public keys into hashmap.
			File globalPublic = new File("../GlobalPublic.txt");
			publicKeys = new HashMap<String, String>();
			
			BufferedReader brGlobal = new BufferedReader(new FileReader(globalPublic));
			String sPublicInfo;
			while ((sPublicInfo=brGlobal.readLine())!=null) {
				// KeyID and Public Key.
				int iSplitPubIndex = sPublicInfo.indexOf("||");
				String sKeyID = sPublicInfo.substring(0, iSplitPubIndex);
				String sPublicKey = sPublicInfo.substring(iSplitPubIndex+2);
				publicKeys.put(sKeyID, sPublicKey);				
			}
			brGlobal.close();
			System.out.println("Loaded public keys of clients and server.");
						
			// Create a server socket listening onto portNo.
			System.out.println("Chat Server binding to port "+portNo+", please wait ...");
			listener = new ServerSocket(portNo, 1, InetAddress.getLocalHost());
			bExit = false;
			System.out.println(listener);
			System.out.println("Server Running:");
			System.out.println("Host = : "+listener.getInetAddress().getHostAddress());
			System.out.println("Port = "+listener.getLocalPort());			
		} catch (BindException e) {
			System.out.println("Port is in use: "+e.getMessage());
			System.exit(0);
		} catch (IOException e) {
			System.out.println("Cannot bind to port "+portNo+": "+e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm specified is invalid.");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("Forming Private Key from string spec is invalid.");
			e.printStackTrace();
		}
	}
	
	private void run() {
		//	While loop that keeps on listening for client connections.
		while (!bExit) {
			try {
				System.out.println("Listening for connection from any client ...");
				addClient(listener.accept());
			} catch(IOException e) {
				System.out.println("Server accept error: "+e.getMessage());
				stop();
			}
		}
	}
	
	private void addClient(Socket toClientSocket) {
		//when a client connects to the server, it is accepted, spawned on a new thread and added to the array of clients
		System.out.println("Client accepted to socket: "+toClientSocket);
		clients.add(new ClientHandlerThread(this, toClientSocket));
		try {
			clients.get(clientCount).open();
			clients.get(clientCount).start();
			clientCount++;
			System.out.println("Number of clients connected = "+clientCount);
		} catch (IOException e) {
			System.out.println("Error opening thread: "+e.getMessage());
		}
	}
	
	public synchronized void handleClientInput(int ID, String input) {
		System.out.println("****************************************************************");
		System.out.println("Message received from client connected at socket "+ID+":");
		System.out.println(input);
		System.out.println("Decrypting and checking message...");
		// Break down message from client.
		// Break string recevied into key, iv and message.
		System.out.println("-----------------------------------------------");
		System.out.println("Breaking message into encoded forms of shared key, initialization vector and compressed formatted message.");
		int iKeyIndex = input.indexOf("|KEY|");
		int iIVIndex = input.indexOf("|IV|");
		int iMsgIndex = input.indexOf("|MSG|");
		
		String sCipherKey = input.substring(iKeyIndex+5, iIVIndex);
		String sIV = input.substring(iIVIndex+4, iMsgIndex);
		String sCipherText = input.substring(iMsgIndex+5);
		System.out.println("Encoded encrypted shared key (radix-64):");
		System.out.println(sCipherKey);
		System.out.println("Encoded initialization vector (radix-64):");
		System.out.println(sIV);
		System.out.println("Encoded encrypted compressed formatted message (radix-64):");
		System.out.println(sCipherText);
		System.out.println("-----------------------------------------------");
		
		// System.out.println("Received:\n"+sCipherKeyReceived);
		// System.out.println(sIVReceived);
		// System.out.println(sCipherTextReceived);
		
		Decoder decoder = Base64.getDecoder();
		
		byte[] encodedSharedKeyBytes = decoder.decode(sCipherKey);
		byte[] IVBytes = decoder.decode(sIV);
		byte[] encodedMsgBytes = decoder.decode(sCipherText);
		
		// Check confidentiality and authentication of message.
		try {
			// Decrpyt shared key with private key of server.
			SecretKey sharedKey = decryptWithPrivateKey(encodedSharedKeyBytes);
			
			// Use shared key to decrypt message to get compressed bytes.
			byte[] compressedMsg = decryptGetCompressMsg(sharedKey, IVBytes, encodedMsgBytes);
			
			// Decompress message.
			byte[] decompressedMsg = decompressMessage(compressedMsg);
			
			 // Decompressed message contains keyID, signature and original message.
			String sDecompressedMessage = new String(decompressedMsg);
			
			System.out.println("Decompressed formatted message: ");
			System.out.println(sDecompressedMessage);
			
			int iKeyIDIndex = sDecompressedMessage.indexOf("|KEYID|");
			int iSignatureIndex = sDecompressedMessage.indexOf("|SIGNATURE|");
			int iMessageIndex = sDecompressedMessage.indexOf("|MESSAGE|");
			
			System.out.println("-----------------------------------------------");
			System.out.println("Breaking formatted message into client's key ID, encoded signed hash, and original message.");
			
			String sKeyID = sDecompressedMessage.substring(iKeyIDIndex+7, iSignatureIndex);
			String sSignatureReceived = sDecompressedMessage.substring(iSignatureIndex+11, iMessageIndex);
			String sMessageReceived = sDecompressedMessage.substring(iMessageIndex+9);
		    
			System.out.println("Key ID of client used to find public key of client:");
			System.out.println(sKeyID);
			
			System.out.println("Encoded signed hash (radix-64):");
			System.out.println(sSignatureReceived);
			
			System.out.println("Received original message:");
			System.out.println(sMessageReceived);
			System.out.println("-----------------------------------------------");
			
			// From original message, come up with message digest to compare.
			byte[] calculatedHash = calculateHash(sMessageReceived);
			
			// Verify if signed digest is the same as digest derived from message with public key.
			boolean isOriginal = verifyMessage(sKeyID, calculatedHash, sSignatureReceived);
			
			System.out.println("Message from client at socket "+ID+" has been decrypted and checked.");
			System.out.println("****************************************************************");
		} catch (InvalidKeyException e) {
			System.out.println("Private Key used to decrypt is invalid.");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm specified is invalid.");
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.out.println("Decrypting with shared key gives bad padding to message.");
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("Block size of shared key encryption is not legal.");
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("Dencryption with shared key resulted in bad padding.");
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Invalid initialization vector argument.");
			e.printStackTrace();
		} catch (DataFormatException e) {
			System.out.println("Error in decompressing received message.");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("Error when compressing message to byte array.");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("Error when forming public key from string.");
			e.printStackTrace();
		} catch (SignatureException e) {
			System.out.println("Error when checking signature of hash.");
			e.printStackTrace();
		}
		
		
	}

	private boolean verifyMessage(String keyID, byte[] calculatedHash, String sSignatureReceived) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		// Get public key of client that signed hash.
		System.out.println("-----------------------------------------------");
		System.out.println("Verifying authenticity of message received using signed hash received and generated hash of message received.");
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		String sClientPublicKey = publicKeys.get(keyID);
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(sClientPublicKey));
	    PublicKey clientPublicKey = keyFactory.generatePublic(publicKeySpec);
		System.out.println("Used Key ID of client to get client's public key to verify signed hash that was signed with client's private key.");
	    // Verify authenticity of message.
		Signature publicSignatureCheck = Signature.getInstance(SIGN_ALGORITHM);
		publicSignatureCheck.initVerify(clientPublicKey);
		publicSignatureCheck.update(calculatedHash);
		
		System.out.println("Verifying signed hash with client's public key and generated hash of message received...");
		
		byte[] signatureBytesReceived = Base64.getDecoder().decode(sSignatureReceived);
		boolean isVerify = publicSignatureCheck.verify(signatureBytesReceived);
		System.out.println("Is the message received authentic by checking the signed hash?");
		if (isVerify) {
			System.out.println(isVerify+" - Yes it is authentic!");
		} else {
			System.out.println(isVerify+" - No it has been intercepted and changed!");
		}
		System.out.println("-----------------------------------------------");
		return isVerify;
	}

	private byte[] calculateHash(String sMessageReceived) throws NoSuchAlgorithmException {
		System.out.println("-----------------------------------------------");
		System.out.println("Generating hash of message received with algorithm: "+HASH_ALGORITHM);
		MessageDigest messageDigestCheck = MessageDigest.getInstance(HASH_ALGORITHM);
		messageDigestCheck.update(sMessageReceived.getBytes());
		byte[] digestCheck = messageDigestCheck.digest();
		System.out.println("Encoded hash of message received using radix-64:");
	    System.out.println(Base64.getEncoder().encodeToString(digestCheck));
	    System.out.println("-----------------------------------------------");
		return digestCheck;
	}

	private byte[] decompressMessage(byte[] compressedMsg) throws DataFormatException, IOException {
		System.out.println("-----------------------------------------------");
		System.out.println("Decompressing compressed formatted message with ZIP algorithm.");	
		Inflater inflater = new Inflater();
		inflater.setInput(compressedMsg);
		ByteArrayOutputStream baosReceived = new ByteArrayOutputStream(compressedMsg.length);
		byte[] tmpBuffer = new byte[1024];
		
		while(!inflater.finished()) {
			int size = inflater.inflate(tmpBuffer);
			baosReceived.write(tmpBuffer,0,size);
		}
		
		byte[] decompressedMessage = baosReceived.toByteArray();
		
		System.out.println("Encoded decompressed formatted message (radix-64):");
	    System.out.println(Base64.getEncoder().encodeToString(decompressedMessage));
		
		System.out.println("Compressed length:\t"+decompressedMessage.length);
		System.out.println("Original length:\t"+compressedMsg.length);
		System.out.println("-----------------------------------------------");
	    
	    baosReceived.close();
	    
	    return decompressedMessage;
	}

	private byte[] decryptGetCompressMsg(SecretKey sharedKey, byte[] IVBytes, byte[] encodedMsgBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("-----------------------------------------------");
		System.out.println("Decrypting compressed formatted message with decrypted shared key and initialization vector.");
		Cipher decipherSymmetric = Cipher.getInstance(SYMMETRIC_ENCRYPTION);
		decipherSymmetric.init(Cipher.DECRYPT_MODE, sharedKey, new IvParameterSpec(IVBytes)); // need IV - initialization vector from encryption.
		byte[] decipherMsg = decipherSymmetric.doFinal(encodedMsgBytes);
		System.out.println("Encoded compressed formatted message (radix-64):");
		System.out.println(Base64.getEncoder().encodeToString(decipherMsg));
		System.out.println("-----------------------------------------------");
		return decipherMsg;
	}

	private SecretKey decryptWithPrivateKey(byte[] encodedSharedKeyBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("-----------------------------------------------");
		System.out.println("Decrypting encrypted shared key with server's private key and creating the shared key.");
		Cipher decipherAsymmetric = Cipher.getInstance(ASYMMETRIC_ENCRYPTION);
		decipherAsymmetric.init(Cipher.DECRYPT_MODE, serverPvtKey);
		byte[] decipherKey = decipherAsymmetric.doFinal(encodedSharedKeyBytes);
		System.out.println("Encoded decrypted one-time shared key (radix-64):");
	    System.out.println(Base64.getEncoder().encodeToString(decipherKey));
		
		SecretKey decipheredSharedKey = new SecretKeySpec(decipherKey, 0, decipherKey.length, "AES");
		
		System.out.println("Recreated one-time shared key instance - SecretKey.");
		System.out.println("-----------------------------------------------");
		return decipheredSharedKey;
	}

	public void stop() {
		// Stop while loop - listening server.
		bExit=true;
	}
	
	public synchronized void removeID(int ID) {
		//removes clientHandler thread if client closes chat application
		int iPos = findClient(ID);
		
		if (iPos>=0) {
			ClientHandlerThread toTerminate = clients.get(iPos);
			System.out.println("Removing client at socket "+ID+"...");
			clients.remove(iPos);
			clientCount--;
			System.out.println("Number of clients connected = "+clientCount);
			try {
				toTerminate.close();
			} catch (IOException e) {
				System.out.println("Error closing thread: "+e.getMessage());
				toTerminate.bStop();
			}
		}
	}	
	
	private int findClient(int ID) {
		//gets index for clientHandler in the clients array
		for(int i=0;i<clients.size();i++) {
			if (clients.get(i).getID()==ID) {
				return i;
			}
		}
		return -1;
	}
	
}
