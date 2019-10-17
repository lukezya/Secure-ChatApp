import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

public class RSAKeyGenerator {

	public static final String RSA_ALGORITHM = "RSA";
	public static final int RSA_KEYSIZE = 2048;
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	public void GenerateRSAKey() {
		// Generate RSA key - key pair: public and private key.
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
			
			// Secure random - random data source for generator.
			keyPairGen.initialize(RSA_KEYSIZE, new SecureRandom()); 
			
			// Generate a RSA keypair with 2048 keysize.
			KeyPair keyPair = keyPairGen.generateKeyPair(); 
			
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
			
			System.out.println("New RSA KeyPair Generated.");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm specified for generating RSA key pair is invalid.");
			e.printStackTrace();
		}
		
	}
	
	public void SaveKeysToFile(String keyID, String filename) {
		Base64.Encoder encoder = Base64.getEncoder();
		
		String sPrivateKey = encoder.encodeToString(privateKey.getEncoded());
		String sPublicKey = encoder.encodeToString(publicKey.getEncoded());
		
		System.out.println("Private Key:\t"+sPrivateKey);
		System.out.println("Public Key:\t"+sPublicKey);
		
		try {
			PrintWriter printWriter = new PrintWriter(filename+"Private.txt");
			printWriter.println(keyID+"||"+sPrivateKey);
			printWriter.close();
		} catch (FileNotFoundException e) {
			System.out.println("Cannot write private key to file. File specified not found.");
			e.printStackTrace();
		} 
		
		try {
			PrintWriter printWriter = new PrintWriter(filename+"Public.txt");
			printWriter.println(keyID+"||"+sPublicKey);
			printWriter.close();
		} catch (FileNotFoundException e) {
			System.out.println("Cannot write public key to file. File specified not found.");
			e.printStackTrace();
		} 
		
		
		System.out.println("Saved Keys to Respective Files.");
	}
	
	
	public static void main(String[] args) {
		RSAKeyGenerator generator = new RSAKeyGenerator();
		generator.GenerateRSAKey();
		generator.SaveKeysToFile(args[0], args[1]);
	}
	
}
