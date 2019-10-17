import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Scanner;
import java.util.zip.Deflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class TcpClient {
	public static final String RSA_ALGORITHM = "RSA";
	public static final String HASH_ALGORITHM = "SHA-256";
	public static final String SIGN_ALGORITHM = "SHA256withRSA";
	public static final String AES_ALGORITHM = "AES";
	public static final int RSA_KEYSIZE = 2048;
	public static final int AES_KEYSIZE = 256;
	
	public static final String ASYMMETRIC_ENCRYPTION = "RSA/ECB/PKCS1Padding";
	public static final String SYMMETRIC_ENCRYPTION = "AES/CBC/PKCS5Padding";
	
	private Socket clientSocket;
    private PrintStream outStream;
    private Scanner scanner;
    
    private PrivateKey clientPvtKey;
    private String KeyID;
    private HashMap<String, String> publicKeys;
    byte[] ivBytes; // For shared key.
    
	private TcpClient(InetAddress serverAddress, int serverPort) {	
		// Load Key ID with private key and public key list.
		try {
			// Load private key from keyring.
			File keyring = new File("../EncryptionPrivate.txt");
			
			BufferedReader brPrivate = new BufferedReader(new FileReader(keyring));
			String privateKeyInfo = brPrivate.readLine();
			brPrivate.close();
			
			int iSplitPvtIndex = privateKeyInfo.indexOf("||");
			
			KeyID = privateKeyInfo.substring(0, iSplitPvtIndex);
			String sPrivateKey = privateKeyInfo.substring(iSplitPvtIndex+2);
			
			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
			
			Base64.Decoder decoder = Base64.getDecoder();
			
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decoder.decode(sPrivateKey));
			clientPvtKey = keyFactory.generatePrivate(privateKeySpec);
			System.out.println("Loaded client's private key with Key ID: "+KeyID+".");
			
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
			
			// Connect to the server.
			if (clientSocket==null) {
				clientSocket = new Socket(serverAddress, serverPort);
				outStream = new PrintStream(clientSocket.getOutputStream());
				scanner = new Scanner(System.in);
				System.out.println("Connected to Server with IP address " + clientSocket.getInetAddress() +" and port "+clientSocket.getPort()+".");
			}
		} catch (ConnectException e) {
			System.out.println("Connection refused. You need to initiate a server first.");
		} catch(UnknownHostException unknownHost){
			System.out.println("You are trying to connect to an unknown host!");
		} catch(IOException ioException){
			ioException.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error when generating RSA keypair, RSA specified algorithm is invalid.");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("Error in generating RSA keypair back from string form.");
			e.printStackTrace();
		}
		
	}
	
	private void start() {
		String message = "";
		while (!message.equals("!!exit")) {
			System.out.println("Type a message to send to the server:");
			message = scanner.nextLine();
			
			if (message.equals("!!exit")) {
				break;
			}
			
			System.out.println("****************************************************************");
			System.out.println("Securing message...");
			// Secure Message.
			String secureMessage = "";
			try {
				// Get hash of message.
				byte[] hashOfMessage = generateHashForMessage(message);
				
				// Sign hash with private key.
				byte[] signedHash = signHash(hashOfMessage);
				
				// Compress signed hash with original message.
				byte[] compressedMessage = compressMessage(signedHash, message);
				
				// Generate a one-time shared key.
				SecretKey sharedKey = generateSharedKey();
				
				// Encrypt compressed message with shared key.
				byte[] encryptCompress = encryptWithSharedKey(sharedKey, compressedMessage);
				
				// Encrypt shared key with public key of server.
				PublicKey serverPublicKey = getServerPublicKey();
				byte[] encryptKey = encryptWithPublicKey(sharedKey, serverPublicKey);
				
				// Create message to send with PGP components.
				secureMessage = formSecureMessage(encryptKey, encryptCompress);
				System.out.println("Transmitting secured message...");
				
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Algorithm specified is invalid.");
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				System.out.println("Private Key used to sign is invalid.");
				e.printStackTrace();
			} catch (SignatureException e) {
				System.out.println("Cannot sign with given key.");
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				System.out.println("Encrypting with shared key gives bad padding to message.");
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				System.out.println("Block size of shared key encryption is not legal.");
				e.printStackTrace();
			} catch (BadPaddingException e) {
				System.out.println("Encryption with shared key resulted in bad padding.");
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				System.out.println("Error when forming public key from string.");
				e.printStackTrace();
			} catch (IOException e) {
				System.out.println("Error when compressing message to byte array.");
				e.printStackTrace();
			}
			
			outStream.println(secureMessage);
			outStream.flush();
			
			System.out.println("****************************************************************");
		}
		System.out.println("Closing connection with server and closing client.");
		
	}

	private byte[] generateHashForMessage(String message) throws NoSuchAlgorithmException {
		// Message digest - hash of message.
		System.out.println("-----------------------------------------------");
		System.out.println("Generating hash of message with algorithm: "+HASH_ALGORITHM);
	    MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM);
	    messageDigest.update(message.getBytes());
	    byte[] digest = messageDigest.digest();
	    //System.out.println(digest);
	    System.out.println("Encoded hash of message using radix-64:");
	    System.out.println(Base64.getEncoder().encodeToString(digest));
	    System.out.println("-----------------------------------------------");
	    return digest;
	}
	
	// Sign hash with private key.
	private byte[] signHash(byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		System.out.println("-----------------------------------------------");
		System.out.println("Signing hash with algorithm: "+SIGN_ALGORITHM);		
		String sPrivateKey = Base64.getEncoder().encodeToString(clientPvtKey.getEncoded());
		System.out.println("Encoded client's private key used to sign hash (radix-64):");
		System.out.println(sPrivateKey);
		
		Signature privateSignature = Signature.getInstance(SIGN_ALGORITHM);
	    privateSignature.initSign(clientPvtKey);
	    privateSignature.update(hash);
	    
	    byte[] signature = privateSignature.sign();
	    String sSignature = Base64.getEncoder().encodeToString(signature);
	    System.out.println("Encoded signed hash of message using client's private key (radix-64):");
	    System.out.println(sSignature);
	    System.out.println("-----------------------------------------------");
	    return signature;
	}
	
	// Compress message with zip algorithm.
	private byte[] compressMessage(byte[] signedHash, String message) throws IOException {
		System.out.println("-----------------------------------------------");
		System.out.println("Compressing with ZIP algorithm.");	
		String sSignature = Base64.getEncoder().encodeToString(signedHash);
		String sCompressedMessage = "|KEYID|"+KeyID+"|SIGNATURE|"+sSignature + "|MESSAGE|"+message;
	    System.out.println("Formatted message to compress:\n"+sCompressedMessage);
	    byte[] compressedMessageBytes = sCompressedMessage.getBytes();
	    
	    Deflater deflater = new Deflater();
	    deflater.setLevel(Deflater.BEST_COMPRESSION);
	    deflater.setInput(compressedMessageBytes);
	    deflater.finish();
	    
	    ByteArrayOutputStream baos = new ByteArrayOutputStream(compressedMessageBytes.length);
	    byte[] tempBuffer = new byte[1024]; // Buffer for compressed data.
	    
	    while (!deflater.finished()) {
	    	int size = deflater.deflate(tempBuffer);
	    	baos.write(tempBuffer, 0, size);
	    }
	    
	    byte[] compressedBytes = baos.toByteArray();
	    
	    System.out.println("Encoded compressed formatted message (radix-64):");
	    System.out.println(Base64.getEncoder().encodeToString(compressedBytes));
	    
	    System.out.println("Original length of formatted message: "+compressedMessageBytes.length);
	    System.out.println("Compressed length of formatted message: "+compressedBytes.length);
	    System.out.println("-----------------------------------------------");
	    
	    baos.close();
	    return compressedBytes;
	}
	
	private SecretKey generateSharedKey() throws NoSuchAlgorithmException {
		// Generate AES key - shared key.
		System.out.println("-----------------------------------------------");
		System.out.println("Generating one-time shared key with algorithm: "+AES_ALGORITHM);
	    KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
	    keyGen.init(AES_KEYSIZE, new SecureRandom());
	    SecretKey sharedKey = keyGen.generateKey();
	    
	    String sSharedKey = Base64.getEncoder().encodeToString(sharedKey.getEncoded());
	    System.out.println("Encoded generated one-time shared key (radix-64):");
	    System.out.println(sSharedKey);
	    System.out.println("-----------------------------------------------");
	    return sharedKey;
	}
	
	private byte[] encryptWithSharedKey(SecretKey sharedKey, byte[] compressedMessage) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("-----------------------------------------------");
		System.out.println("Encrypting compressed formatted message with shared key using AES algorithm in CBC mode with PKCS5 padding.");
		Cipher cipherSymmetric = Cipher.getInstance(SYMMETRIC_ENCRYPTION);
	    cipherSymmetric.init(Cipher.ENCRYPT_MODE, sharedKey);
	    ivBytes = cipherSymmetric.getIV();
	    
	    byte[] cipherText = cipherSymmetric.doFinal(compressedMessage);
	    System.out.println("Encoded encrypted compressed formatted message (radix-64):");
	    System.out.println(Base64.getEncoder().encodeToString(cipherText));
	    System.out.println("-----------------------------------------------");
	    return cipherText;
	}
	
	private PublicKey getServerPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		String sServerPublicKey = publicKeys.get("SERVER");
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(sServerPublicKey));
	    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	    return publicKey;
	}
	
	private byte[] encryptWithPublicKey(SecretKey sharedKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("-----------------------------------------------");
		System.out.println("Encrypting shared key with server's public key using RSA algorithm in ECB mode with PKCS1 padding");
		Cipher cipherAsymmetric = Cipher.getInstance(ASYMMETRIC_ENCRYPTION);
		cipherAsymmetric.init(Cipher.ENCRYPT_MODE, publicKey);
		cipherAsymmetric.update(sharedKey.getEncoded());
		byte[] cipherKey = cipherAsymmetric.doFinal();
		System.out.println("Encoded encrypted shared key (radix-64):");
	    System.out.println(Base64.getEncoder().encodeToString(cipherKey));
		System.out.println("-----------------------------------------------");
		return cipherKey;
	}
	
	private String formSecureMessage(byte[] encryptKey, byte[] encryptCompress) {
		Encoder encoder = Base64.getEncoder();
		String sCipherText = encoder.encodeToString(encryptCompress);
		String sCipherKey = encoder.encodeToString(encryptKey);
		String sIV = encoder.encodeToString(ivBytes);
		String sSecureMessage = "|KEY|"+sCipherKey+
								"|IV|"+sIV+
								"|MSG|"+sCipherText;
		System.out.println("Secure message to transmit:");
		System.out.println(sSecureMessage);
		return sSecureMessage;
	}
	
	public static void main(String[] args) {
		try {
			// Create a client and connect to server's IP address and port number.
			TcpClient client = new TcpClient(InetAddress.getByName(args[0]), Integer.parseInt(args[1]));
			// Start waiting for input to secure and transmit.			
			client.start();
		} catch (NumberFormatException e) {
			System.out.println("Error connecting to server. Hostname given has NumberFormatException.");
			e.printStackTrace();
		} catch (UnknownHostException e) {
			System.out.println("Error connecting to server. Cannot identify IP address given.");
			e.printStackTrace();
		}
	}

}
