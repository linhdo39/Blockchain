import java.io.*;  
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.io.StringWriter;
import java.io.StringReader;
import java.io.BufferedReader;
import java.security.*;
import java.security.Security;
import java.text.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

class ProcessBlock{
	int processID;
	byte[] pubKey;
	
	public int getPID(){
		return this.processID;
	}
	public void setProcessID (int pid) {
		this.processID = pid;
	}
	
	public void setPubKey (String input) {
		Gson gson = new Gson();
		String convert = gson.fromJson(input, String.class);
		byte[] pubKey = Base64.getDecoder().decode(convert);
		this.pubKey = pubKey;
	}
}

class Ports {
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(int PID){
		KeyServerPort = KeyServerPortBase + PID;
		UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + PID;
		BlockchainServerPort = BlockchainServerPortBase + PID;
    }
}

class BlockRecord implements Serializable{
	String BlockID;
	String TimeStamp;
	String VerificationProcessID;
	String PreviousHash; 
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String RandomSeed;
	String Hash;
	String Diag;
	String Treat;
	String Rx;
		
	public String getBlockID() {return BlockID;}
	public void setBlockID(String BID){this.BlockID = BID;}

	public String getTimeStamp() {return TimeStamp;}
	public void setTimeStamp(String TS){this.TimeStamp = TS;}

	public String getVerificationProcessID() {return VerificationProcessID;}
	public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
  
	public String getPreviousHash() {return this.PreviousHash;}
	public void setPreviousHash (String PH){this.PreviousHash = PH;}

	public String getLname() {return Lname;}
	public void setLname (String LN){this.Lname = LN;}
  
	public String getFname() {return Fname;}
	public void setFname (String FN){this.Fname = FN;}
  
	public String getSSNum() {return SSNum;}
	public void setSSNum (String SS){this.SSNum = SS;}
  
	public String getDOB() {return DOB;}
	public void setDOB (String RS){this.DOB = RS;}

	public String getDiag() {return Diag;}
	public void setDiag (String D){this.Diag = D;}

	public String getTreat() {return Treat;}
	public void setTreat (String Tr){this.Treat = Tr;}

	public String getRx() {return Rx;}
	public void setRx (String Rx){this.Rx = Rx;}

	public String getRandomSeed() {return RandomSeed;}
	public void setRandomSeed (String RS){this.RandomSeed = RS;}
  
	public String getHash() {return Hash;}
	public void setHash (String input){this.Hash = input;}	
  
	
	public String getData(){
		String data = Fname + Lname + SSNum + DOB + Diag + Treat + Rx + PreviousHash + TimeStamp;
		return data;
  }
}

class PublicKeyWorker extends Thread { 
    Socket keySock; 
    PublicKeyWorker (Socket s) {keySock = s;} 
    
	public void run(){
		ProcessBlock PB = new ProcessBlock();
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
			for (int i = 0; i <2; ++i){
				String data = in.readLine ();
				if( i == 0)
					PB.setProcessID(Integer.parseInt(data));
				else {
					PB.setPubKey(data);
					if(PB.getPID() == miniBlock.PID) {
						Gson gson = new Gson();
						String convert = gson.fromJson(data, String.class);
						System.out.println("The public key for process " + miniBlock.PID +" is "
											+ convert);
					}
				}
			}
			for (ProcessBlock element: miniBlock.processBlock){
				if(element.getPID() != PB.getPID()) {
					miniBlock.processBlock.add(PB);
					break;
				}
			}
			keySock.close(); 
		} catch (IOException x){x.printStackTrace();}
    }
}

class PublicKeyServer implements Runnable {
    //public ProcessBlock[] PBlock = new ProcessBlock[3]; // Typical would be: One block to store info for each process.
    
    public void run(){
	int q_len = 6;
	Socket keySock;
	System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
	try{
	    ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
	    while (true) {
		keySock = servsock.accept();
		new PublicKeyWorker (keySock).start(); 
	    }
	}catch (IOException ioe) {System.out.println(ioe);}
    }
}   
 

class UnverifiedBlockServer implements Runnable {
    PriorityBlockingQueue<BlockRecord> queue;
    UnverifiedBlockServer(PriorityBlockingQueue<BlockRecord> queue){
		this.queue = queue; 
    }

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>(){
		@Override
		public int compare(BlockRecord b1, BlockRecord b2) {
			String s1 = b1.getTimeStamp();
			String s2 = b2.getTimeStamp();
			if (s1 == s2) {return 0;}
			if (s1 == null) {return -1;}
			if (s2 == null) {return 1;}
			return s1.compareTo(s2);
		}
    };

  
    /* Inner class to share priority queue. We are going to place the unverified blocks (UVBs) into this queue in the order
       we get them, but they will be retrieved by a consumer process sorted by TimeStamp of when created. */ 

	class UnverifiedBlockWorker extends Thread { 
		Socket sock; 
		UnverifiedBlockWorker (Socket s) {sock = s;} 
		BlockRecord BR = new BlockRecord();
    
		public void run(){
			try{
				ObjectInputStream unverifiedIn = new ObjectInputStream(sock.getInputStream());
				BR = (BlockRecord) unverifiedIn.readObject(); 
				System.out.println("Received UVB: " + BR.getTimeStamp());
				queue.put(BR); 
				sock.close(); 
			} catch (Exception x){x.printStackTrace();}
		}
	}
  
	public void run(){
		int q_len = 6;
		Socket sock;
		System.out.println("Starting the Unverified Block Server input thread using " +
		       Integer.toString(Ports.UnverifiedBlockServerPort));
		
		try{
			ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
			while (true) {
				sock = UVBServer.accept(); 
				System.out.println("Got connection to UVB Server.");
				new UnverifiedBlockWorker(sock).start(); 
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}

  
/* We have received unverified blocks into a thread-safe concurrent access queue. For this example, we retrieve them
   in order according to their TimeStamp of when created. It must be concurrent safe because two or more threads modifiy it
   "at once," (mutiple worker threads to add to the queue, and a consumer thread to remove from it).*/

class UnverifiedBlockConsumer implements Runnable {
	BlockingQueue<BlockRecord> queue; // Passed from BC object.
	int PID;
	UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue){
		this.queue = queue; // Constructor binds our priority queue to the local variable.
	}
	
	public void run(){
		String previousHash = "0000000";
		PrintStream toBlockChainServer;
		Socket BlockChainSock;
		BlockRecord tempRec;
		
		System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
		try{
			while(true){ // Consume from the incoming UVB queue. Do the (fake here) work to verify. Mulitcast new blockchain
				tempRec = queue.take(); // Pop the next BlockRecord from the queue. Will blocked-wait on empty queue
				System.out.println("Consumer got unverified: " + tempRec.getFname() +" " + tempRec.getLname());
				previousHash = Work.getHash();
				Work test = new Work(tempRec);
				if(test.proofWork() == true) {
					tempRec.setHash(test.getHash());
					tempRec.setRandomSeed(test.getSeed());
					tempRec.setPreviousHash(previousHash);
					tempRec.setVerificationProcessID(Integer.toString(miniBlock.PID));
					
					for(int i=0; i < miniBlock.numProcesses; i++){ // Send to each process in group, including THIS process:
						BlockChainSock = new Socket(miniBlock.serverName, Ports.BlockchainServerPortBase + i);
						toBlockChainServer = new PrintStream(BlockChainSock.getOutputStream());
						Gson gson = new GsonBuilder().setPrettyPrinting().create();
						toBlockChainServer.println(gson.toJson(tempRec)); 
						toBlockChainServer.flush();
						BlockChainSock.close();
					}
				}
				Thread.sleep(1500);
			}
		}catch (Exception e) {System.out.println(e);}
	}
}

class Work {
	static BlockRecord tempRec;
	public Work(BlockRecord tempRec) {
		this.tempRec= tempRec;
		
	}
	public static String ByteArrayToString(byte[] ba){
		StringBuilder hex = new StringBuilder(ba.length * 2);
		for(int i=0; i < ba.length; i++){
			hex.append(String.format("%02X", ba[i]));
		}
		return hex.toString();
	}

	public static String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}
  
	private static final String ALPHA_NUMERIC_STRING = "abcdefghijklmopqrstuvwzyxABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static String randString;
	static String stringOut; // Will contain the new SHA256 string converted to HEX and printable.
	static Random r = new Random();
	
	public static boolean proofWork(){
		String concatString = "";  // Random seed string concatenated with the existing data

		randString = randomAlphaNumeric(8);
		int workNumber = 0;     // Number will be between 0000 (0) and FFFF (65535), here's proof:
		workNumber = Integer.parseInt("0000",16); // Lowest hex value
		workNumber = Integer.parseInt("FFFF",16); // Highest hex value
		int n = 0;	
		for(BlockRecord temp: miniBlock.Blockchain){
			if(temp.getFname() == tempRec.getFname() && temp.getLname() == tempRec.getLname() && temp.getDOB() == tempRec.getDOB()) 
				n++;
		}
		
		if(n != 0) {
			return false;
		}
		try {
		
			for(int i=1; i<20; i++){ // Limit how long we try for this example.
				randString = randomAlphaNumeric(8); // Get a new random AlphaNumeric seed string
				concatString = tempRec.getData() + randString; // Concatenate with our input string (which represents Blockdata)
				MessageDigest MD = MessageDigest.getInstance("SHA-256");
				byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); // Get the hash value
				
				stringOut = ByteArrayToString(bytesHash); // Turn into a string of hex values, java 1.9 

				workNumber = Integer.parseInt(stringOut.substring(0,4),16); // Between 0000 (0) and FFFF (65535)
				
				n = 0;	
				for(BlockRecord temp: miniBlock.Blockchain){
					if(temp.getFname() == tempRec.getFname()) 
						n++;
				}
		
				if(n != 0) {
					return false;
				}
				
				if (workNumber < 10000){
					break;
				}
			}
			Thread.sleep((r.nextInt(9) * 100));
		}catch(Exception ex) {ex.printStackTrace();}
		return true;
	}
	
	public static String getHash(){
		return stringOut;
	}
	public static String getSeed(){
		return randString;
	}
}

class BlockchainWorker extends Thread { 
    Socket sock; 
    BlockchainWorker (Socket s) {sock = s;} 
    public void run(){
	try{
	    BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
	    String blockData = "";
	    String blockDataIn;
	    while((blockDataIn = in.readLine()) != null){
			blockData += blockDataIn;				
	    }
		Gson gson = new Gson();
		BlockRecord br = gson.fromJson(blockData, BlockRecord.class);
		miniBlock.Blockchain.add(br);
		System.out.println(miniBlock.Blockchain);
		gson = new Gson();
		if(miniBlock.PID == 0) {
			try (FileWriter writer = new FileWriter("BlockchainLedgerSample.json")) {
					gson.toJson(miniBlock.Blockchain, writer);
			} catch (IOException e) {
					e.printStackTrace();
			}	
		}
	    sock.close(); 
		
	} catch (IOException x){x.printStackTrace();}
    }
}

class BlockchainServer implements Runnable {
    public void run(){
	int q_len = 6; 
	Socket sock;
	System.out.println("Starting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
	try{
	    ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
	    while (true) {
		sock = servsock.accept();
		new BlockchainWorker (sock).start(); 
	    }
	}catch (IOException ioe) {System.out.println(ioe);}
    }
}

class marshalsJson {
	String FileName = null;
	public static String writeToJson(BlockRecord input){
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		String json = gson.toJson(input);
		return json;
	}
	
	public static BlockRecord readJson (String input) {
		Gson gson = new Gson();
		BlockRecord br = gson.fromJson(input, BlockRecord.class);
		return br;
	}
	
	public static String writeLedgerJson (PriorityBlockingQueue<BlockRecord> list) {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		String json = gson.toJson(list);
		try (FileWriter writer = new FileWriter("BlockchainLedgerSample.json")) {
			gson.toJson(list, writer);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return json; 
	}
	
	public static PriorityBlockingQueue<BlockRecord> readLedgerJson (String input) {
		PriorityBlockingQueue<BlockRecord> blockRecordIn = null;
		Gson gson = new Gson();
		try  (Reader reader = new FileReader("BlockchainLedgerSample.json")) {
			blockRecordIn = gson.fromJson(reader, new TypeToken<LinkedList<BlockRecord>>(){}.getType());
			return blockRecordIn;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return blockRecordIn;
	}
}

public class miniBlock {
	public static String serverName = "localhost";
	static String blockchain = ""; 
	public static ArrayList<ProcessBlock> processBlock = new ArrayList<>();
	public static int PID;
	public static int numProcesses = 1;
	
	public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>(){
		@Override
		public int compare(BlockRecord b1, BlockRecord b2){
			String s1 = b1.getTimeStamp();
			String s2 = b2.getTimeStamp();
			if (s1 == s2) {return 0;}
			if (s1 == null) {return -1;}
			if (s2 == null) {return 1;}
			return s1.compareTo(s2);
		}
    };
	
	final static PriorityBlockingQueue<BlockRecord> Blockchain = new PriorityBlockingQueue<>(100, BlockTSComparator);
	final static PriorityBlockingQueue<BlockRecord> PriorityQueue = new PriorityBlockingQueue<>(100, BlockTSComparator);
	
	class cryption{
		public boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initVerify(key);
			signer.update(data);
			return (signer.verify(sig));
		}	
		
		public byte[] signData(byte[] data, PrivateKey key) throws Exception {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(key);
			signer.update(data);
			return (signer.sign());
		}
    }
	
	
	public KeyPair generateKeyPair() {
		KeyPair pair = null;
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
			rng.setSeed(new Random().nextInt(100));
			keyGenerator.initialize(1024, rng);
			pair = keyGenerator.generateKeyPair();
			return pair;
		} catch (Exception e) {}
		return pair;
	}
	
	
	public static void input(){
		int iFNAME = 0;
		int iLNAME = 1;
		int iDOB = 2;
		int iSSNUM = 3;
		int iDIAG = 4;
		int iTREAT = 5;
		int iRX = 6;
		int UnverifiedBlockPort;
		int BlockChainPort;
		String FILENAME;

		UnverifiedBlockPort = 4710 + PID;
		BlockChainPort = 4820 + PID;
    
		System.out.println("Process number: " + PID + " Ports: " + UnverifiedBlockPort + " " + 
		       BlockChainPort + "\n");

		switch(PID){
			case 1: FILENAME = "BlockInput1.txt"; break;
			case 2: FILENAME = "BlockInput2.txt"; break;
			default: FILENAME= "BlockInput0.txt"; break;
		}

		System.out.println("Using input file: " + FILENAME);

		try {
			BufferedReader br = new BufferedReader(new FileReader(FILENAME));
			String[] tokens = new String[10];
			String InputLineStr;
			String suuid;
			UUID idA;
			BlockRecord tempRec;
      
			StringWriter sw = new StringWriter();
      
			int n = 0;
      
			while ((InputLineStr = br.readLine()) != null) {
	
				BlockRecord BR = new BlockRecord(); 
				try{Thread.sleep(1001);}catch(InterruptedException e){}
				Date date = new Date();
				String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
				String TimeStampString = T1 + "." + PID; 
				BR.setTimeStamp(TimeStampString); 

	
			/* CDE: Generate a unique blockID. This would also be signed by creating process: */
				suuid = new String(UUID.randomUUID().toString());
				BR.setBlockID(suuid);
			/* CDE put the file data into the block record: */
				tokens = InputLineStr.split(" +"); // Tokenize the input
				BR.setFname(tokens[iFNAME]);
				BR.setLname(tokens[iLNAME]);
				BR.setSSNum(tokens[iSSNUM]);
				BR.setDOB(tokens[iDOB]);
				BR.setDiag(tokens[iDIAG]);
				BR.setTreat(tokens[iTREAT]);
				BR.setRx(tokens[iRX]);
				PriorityQueue.add(BR);
				n++;
			}
		}catch (IOException e) {e.printStackTrace();}
	}
	
	public static void KeySend (KeyPair pair){ 
		Socket sock;
		PrintStream toServer;
		try{
			for(int i=0; i< numProcesses; i++){// Send our public key to all servers.
				sock = new Socket(serverName, Ports.KeyServerPortBase + i);
				toServer = new PrintStream(sock.getOutputStream());
				byte[] byte_key = pair.getPublic().getEncoded();
				String publicKey = Base64.getEncoder().encodeToString(byte_key);
				Gson gson = new GsonBuilder().setPrettyPrinting().create();
				String json = gson.toJson(publicKey);
				toServer.println(PID);
				toServer.println(json);
				toServer.flush();
				sock.close();
			}
		}catch (Exception x) {x.printStackTrace ();}
    }

    public void UnverifiedSend (){ // Multicast some unverified blocks to the other processes

		Socket UVBsock; // Will be client connection to the Unverified Block Server for each other process.
		BlockRecord tempRec;
		Random r = new Random();
      
		//Thread.sleep(1000); // wait for public keys to settle, normally would wait for an ack that it was received.
	
		try{
			miniBlock.input();
			Iterator<BlockRecord> iterator = PriorityQueue.iterator();

			ObjectOutputStream toServerOOS = null; // Stream for sending Java objects
			for(int i = 0; i < numProcesses; i++){// Send some sample Unverified Blocks (UVBs) to each process
				System.out.println("Sending UVBs to process " + i + "...");
				iterator = PriorityQueue.iterator(); // We saved our samples in a list, restart at the beginning each time.
				while(iterator.hasNext()){
					// Client connection. Triggers Unverified Block Worker in other process's UVB server:
					UVBsock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
					toServerOOS = new ObjectOutputStream(UVBsock.getOutputStream());
					Thread.sleep((r.nextInt(9) * 100)); // Sleep up to a second to randominze when sent.
					tempRec = iterator.next();
					toServerOOS.writeObject(tempRec); // Send the unverified block record object
					toServerOOS.flush();
					UVBsock.close();
				} 
			}
	    
			Thread.sleep((r.nextInt(9) * 100)); // Sleep up to a second to randominze when sent.
		
		}catch (Exception x) {x.printStackTrace ();}
    }
	
	public static void main(String args[]){
		miniBlock block = new miniBlock();
		block.run(args);
	}
	
	public static void run (String args[]){
		if (args.length < 1)
			PID = 0;
		else
			PID = Integer.parseInt(args[0]);
		
		System.out.println("Linh Do's Block Coordination Framework. Use Control-C to stop the process.\n");
		System.out.println("Using processID " + PID + "\n");
		
		//dummy block (genesis block)
		/*BlockRecord br = new BlockRecord();
		String suuid = new String(UUID.randomUUID().toString());
		br.setBlockID(suuid);
		br.setFname("First");
		br.setLname("Block");
		br.setSSNum("783-12-2189");
		br.setDOB("1990.03.07");
		br.setDiag("Diagnose");
		br.setTreat("Treatment");
		br.setRx("Rx");
		Date date = new Date();
		String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
		String TimeStampString = T1 + "." + PID; 
		System.out.println("Timestamp: " + TimeStampString);
		br.setTimeStamp(TimeStampString);
		br.setVerificationProcessID("0");
		br.setPreviousHash("0000000");
		Work test = new Work(br);
		br.setRandomSeed(test.randString);
		br.setHash(test.stringOut);
		
		PriorityQueue.add(br);*/
		
		KeyPair pair = new miniBlock().generateKeyPair(); 	
		new Ports().setPorts(PID);		
		new Thread(new PublicKeyServer()).start();  
		new Thread(new UnverifiedBlockServer(PriorityQueue)).start(); 
		new Thread(new BlockchainServer()).start(); 
		try{
			Thread.sleep(1000);
		}catch(Exception e){} 
		
		KeySend(pair);
		
		try{
			Thread.sleep(1000);
		}catch(Exception e){} 
		
		new miniBlock().UnverifiedSend();
		
		try{
			Thread.sleep(1000);
		}catch(Exception e){}
		
		new Thread(new UnverifiedBlockConsumer(PriorityQueue)).start(); 
		
		try{Thread.sleep(1000);}catch(Exception e){}
	}		
}