import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;

public class ClientHandlerThread extends Thread {
	private TcpServer chatServer = null;
	private Socket uniqSocket = null;
	// ID to distinguish between different client handlers.
	private int ID = -1;
	// Boolean for stopping thread - while loop terminator.
	private volatile boolean bExit = false;
	private DataInputStream inStream = null;
	
	public ClientHandlerThread(TcpServer chatServer, Socket uniqSocket) {
		// Initialize fields.
		super();
		this.chatServer = chatServer;
		this.uniqSocket = uniqSocket;
		ID = uniqSocket.getPort();
	}
	
	// Getters.
	public int getID() {
		return ID;
	}
	
	public void open() throws IOException {
		// Open input streams to get message from client.
		inStream = new DataInputStream(uniqSocket.getInputStream());
	}
	
	public void close() throws IOException {
		// Destructor of thread.
		bStop();
		if (inStream != null)  
			inStream.close();
		if (uniqSocket != null)    
			uniqSocket.close();
	}
	
	@SuppressWarnings("deprecation")
	public void run() {
		// Keeps on listening for user input
		System.out.println("Server Thread with Socket " + ID + " running.");
		while (!bExit) {
			try {
				chatServer.handleClientInput(ID, inStream.readLine()); //method used as specified in notes of assignment 2
			} catch(IOException e) {
				System.out.println(ID+" Error reading from client: "+e.getMessage());
				chatServer.removeID(ID);
			} catch (NullPointerException e) {
				System.out.println(ID+" Error reading from client: "+e.getMessage());
				chatServer.removeID(ID);
			}
		}
	}
	
	public void bStop() {
		// Stopping while loop of thread.
		bExit=true;
	}
}
