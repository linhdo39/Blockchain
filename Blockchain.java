/*--------------------------------------------------------

1. Name / Date:
My Linh Do / 03.03.2021

2. Java version used, if not the official version for the class:

build 10.0.2+13

3. Precise command-line compilation examples / instructions:

> javac -cp "gson-2.8.2.jar" Blockchain.java

4. Precise examples / instructions to run this program:

>start java -cp ".;gson-2.8.2.jar" Blockchain 0
> start java -cp ".;gson-2.8.2.jar" Blockchain 1
>java -cp ".;gson-2.8.2.jar" Blockchain 2


5. List of files needed for running the program.

checklist-block.html
Blockchain.java
BlockchainLog.txt
BlockchainLedgerSample.json
BlockInput0.txt, BlockInput1.txt, BlockInput2.txt

6. Notes:
The code is not completed so there are a lot of bugs. For the basic of block chain, the code works well when it is only 
one process. When the other two processes involves, I haven't had trouble running it but it would occasionally produce a ledger
with duplicate value. The duplicated block record happened when I ran it because the time stamp is identical to each 
other so the program could not sorted it out prior. 

For the digital key, I was able to do simple implementation with it by using a short string.
I used a lot of the ultilities codes with some modifications. 

Credit web source code:
https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html
https://dzone.com/articles/generate-random-alpha-numeric
----------------------------------------------------------*/
//import java library
import java.io.*;  
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.io.StringWriter;
import java.io.StringReader;
import java.io.BufferedReader;
import java.security.*;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.text.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

//to store the process ID and their corresponding public key
class ProcessBlock{
	int processID;
	byte[] pubKey;
	
	public int getPID(){
		return this.processID;
	}
	
	//method to restore the public key from byte array
	public PublicKey getPubKey(){
		PublicKey RestoredKey = null;
		try {
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RestoredKey = keyFactory.generatePublic(pubSpec);
			return RestoredKey;
		} catch (Exception e) {}
		return RestoredKey;
	}
	public void setProcessID (int pid) {
		this.processID = pid;
	}
	
	public void setPubKey (String input) {
		Gson gson = new Gson();					
		String convert = gson.fromJson(input, String.class);		//convert Json object to string
		byte[] pubKey = Base64.getDecoder().decode(convert);		//convert the string back the byte format
		this.pubKey = pubKey;
	}
}

//to store all the port numbers 
class Ports {			
    public static int KeyServerPortBase = 4710;					//to receive public key
    public static int UnverifiedBlockServerPortBase = 4820;		//to receive UVB
    public static int BlockchainServerPortBase = 4930;			//to receive the block chain
	public static int BlockLedgerServerPortBase = 5120;			//to receive the block ledger 

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;
	public static int BlockLedgerServerPort;

    public void setPorts(int PID){
		KeyServerPort = KeyServerPortBase + PID;
		UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + PID;
		BlockchainServerPort = BlockchainServerPortBase + PID;
		BlockLedgerServerPort = BlockLedgerServerPortBase + PID;
    }
}

//Block record class with all its attributes
class BlockRecord implements Serializable{
	String BlockID;
	String Hash;
	String TimeStamp;
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String favorite_show;
	String steamingService;
	String NextShow;
	String VerificationProcessID;
	String PreviousHash; 
	String RandomSeed;
	String creatorProcess;
	byte [] creatorSigned;
	
	//getter and setter functions
	public void setBlockID(String BID){this.BlockID = BID;}
	public void setTimeStamp(String TS){this.TimeStamp = TS;}
	public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
	public void setPreviousHash (String PH){this.PreviousHash = PH;}
	public void setLname (String LN){this.Lname = LN;}
	public void setFname (String FN){this.Fname = FN;}
	public void setSSNum (String SS){this.SSNum = SS;}
	public void setDOB (String RS){this.DOB = RS;}
	public void setfavorite_show (String str){this.favorite_show = str;}
	public void setsteamingService (String str){this.steamingService = str;}
	public void setNextShow (String NextShow){this.NextShow = NextShow;}
	public void setRandomSeed (String RS){this.RandomSeed = RS;}
	public void setHash (String input){this.Hash = input;}	
	public void setCreatorProcess(String input){this.creatorProcess = input;}
	public void setCreatorSigned (byte[] input) {this.creatorSigned = input;}
  
	public String getTimeStamp() {return TimeStamp;}
	public String getPreviousHash() {return this.PreviousHash;}
	public String getLname() {return this.Lname;}
	public String getFname() {return this.Fname;}
	public String getHash() {return this.Hash;}
	public String getCreator() {return this.creatorProcess;}
	public byte [] getCreatorSigned() {return this.creatorSigned;}
	
	//this reduces the time the work has to search to concatenate the data
	public String getData(){
		String data = BlockID + Fname + Lname + SSNum + DOB + favorite_show + steamingService + NextShow + PreviousHash + TimeStamp;
		return data;
	}
}

//to process the public key received from the socket
class PublicKeyWorker extends Thread { 
    Socket keySock; 
    PublicKeyWorker (Socket s) {keySock = s;} 	//constructor for PublicKeyWorker
    
	public void run(){
		ProcessBlock PB = new ProcessBlock();
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
			for (int i = 0; i <2; ++i){			
				String data = in.readLine ();
				if(i == 0)										//since I sent PID and public key separately, this is to 
					PB.setProcessID(Integer.parseInt(data));	//make sure the information received is inputted correctly
				else {
					PB.setPubKey(data);							//set public key in processBlock 
					if(PB.getPID() == Blockchain.PID) {
						Gson gson = new Gson();
						String convert = gson.fromJson(data, String.class);			//convert the json object to string of public key
						System.out.println("The public key for process " + Blockchain.PID +" is "
											+ convert);			//print out public key
					}
				}
			}
			
			// to keep track of the public key for each process to ensure the validity of the block
			for (ProcessBlock element: Blockchain.processBlock){
				if(element.getPID() != PB.getPID()) {
					Blockchain.processBlock.add(PB);
					break;
				}
			}
			keySock.close(); 
		} catch (IOException x){x.printStackTrace();} //for any exception
    }
}

//class to start the public key server
class PublicKeyServer implements Runnable {
        
    public void run(){
		int q_len = 6;
		Socket keySock;
		System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len); 	//start a server
			while (true) {															//listen to and accept request from socket
				keySock = servsock.accept();
				new PublicKeyWorker (keySock).start(); 								//start a new worker
			}
		}catch (IOException ioe) {System.out.println(ioe);}							//for any exception
    }
}   
 
//to store all the block record received from the socket for later use 
class UnverifiedBlockServer implements Runnable {
    PriorityBlockingQueue<BlockRecord> queue;		
    UnverifiedBlockServer(PriorityBlockingQueue<BlockRecord> queue){
		this.queue = queue; 
    }
	
	//to process the unverified block received from the socket and then add them to a queu
    class UnverifiedBlockWorker extends Thread { 
		Socket sock; 
		UnverifiedBlockWorker (Socket s) {sock = s;} 
		
		public void run(){
			String blockDataIn;
			String blockData ="";
			try{
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				while((blockDataIn = in.readLine()) != null){		//read in the information from the socket
						blockData += blockDataIn;					//retrieve the json string				
				}
				Gson gson = new Gson();		
				BlockRecord BR = gson.fromJson(blockData, BlockRecord.class);		//convert the json string back to Block record type
				System.out.println("Received UVB: " + BR.getTimeStamp());			//print out the time received the block record
				queue.put(BR);														//put the block record into the Priority queue
				sock.close(); 
			} catch (Exception x){}						//for any exception
		}
	}
  
	public void run(){
		int q_len = 6;
		Socket sock;
		System.out.println("Starting the Unverified Block Server input thread using " +
		       Integer.toString(Ports.UnverifiedBlockServerPort));
		
		try{
			ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);		//start a new server
			while (true) {														//listen to and accept request from socket
				sock = UVBServer.accept(); 
				System.out.println("Got connection to UVB Server.");
				new UnverifiedBlockWorker(sock).start(); 						//start a new worker 
			}
		}catch (IOException ioe) {System.out.println(ioe);}						//for any exception
	}
}

//to consume the block received from the socket
class UnverifiedBlockConsumer implements Runnable {
	BlockingQueue<BlockRecord> queue; 
	UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue){
		this.queue = queue; 
	}
	
	public void run(){
		String previousHash;							//to get previous hash
		PrintStream toBlockChainServer;					//to send information to the server
		Socket BlockChainSock;							//socket
		BlockRecord tempRec,temp = null;				//temporary block record
		boolean verified = true;						//for signature verification
		System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
		try{
			while(true){
				tempRec = queue.take(); 	// take the first element from the queue
				System.out.println("Consumer got unverified: " + tempRec.getFname() +" " + tempRec.getLname());
				if(Blockchain.blockchain.indexOf(tempRec.getData().substring(1, 9)) > 0)		//check if the temp record is already in the block chain or not 
					continue;
				//go through the process block array, which contains all the public keys and the corresponsing process ID
				for(ProcessBlock block: Blockchain.processBlock) {
					//if the process ID matches with the unverified block record's creator ID
					if(block.getPID() == Integer.parseInt(tempRec.getCreator())){
						//set the value of verified to watch the method return
						verified = Blockchain.verifySig(Blockchain.sign.getBytes(), block.getPubKey(), tempRec.getCreatorSigned());
						break;
					}
				}				
				if(verified) {
					//this function is to check the last item in the BlockchainQueue
					//I added this in because before the blockchain would not "link" to each other
					//this minimized the problem but occasionally there will be two blocks's previous hash value 
					//point to the same hash value.
					Iterator<BlockRecord> iterator = Blockchain.BlockchainQueue.iterator(); 
					while(iterator.hasNext()){ 
						temp = iterator.next();
					} 	
					
					tempRec.setPreviousHash(temp.getHash());
					Work test = new Work(tempRec);				//do some work here
					if(test.proofWork() == true) {				//if the proof of Work is valid and the block is not already in the block chain
						tempRec.setHash(test.getHash());		//set the Hash number
						tempRec.setRandomSeed(test.getSeed());	//set the winning seed
						tempRec.setVerificationProcessID(Integer.toString(Blockchain.PID));		//set the winning process ID number	
						
						if(Blockchain.blockchain.indexOf(tempRec.getData().substring(1, 9)) < 0) {		//check again for duplicate in the block chain 
							Blockchain.blockchain+=tempRec.getData();
						}
						
						//send the string of block chain and send the temporary block record to the blockChainServer in json object
						//to every server port including the current one
						for(int i=0; i < Blockchain.numProcesses; i++){
							BlockChainSock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + i);
							toBlockChainServer = new PrintStream(BlockChainSock.getOutputStream());
							toBlockChainServer.println(Blockchain.blockchain);
							Gson gson = new GsonBuilder().setPrettyPrinting().create();
							toBlockChainServer.println(gson.toJson(tempRec)); 
							toBlockChainServer.flush();
							BlockChainSock.close();
						}
					}
				}
				Thread.sleep(1500);
			}
		}catch (Exception e) {System.out.println(e);}
	}
}


//class to do work and calculate hash value
class Work {
	static BlockRecord tempRec;
	public Work(BlockRecord tempRec) {
		this.tempRec= tempRec;
	}
	
	//to turn a byte array to string 
	public static String ByteArrayToString(byte[] ba){
		StringBuilder hex = new StringBuilder(ba.length * 2);
		for(int i=0; i < ba.length; i++){
			hex.append(String.format("%02X", ba[i]));
		}
		return hex.toString();
	}
	
	//to generate a random string
	public static String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}
  
	private static final String ALPHA_NUMERIC_STRING = "abcdefghijklmopqrstuvwzyxABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static String randString;					//random string that will contain the winning seed
	static String stringOut = ""; 				//to store the SHA256 hash value
	static Random r = new Random();
	
	public static boolean proofWork(){
		String data = "";  
		randString = randomAlphaNumeric(8);
		int workNumber = 0;   
		
		//check if the temp record is already in the block chain string or not
		if(Blockchain.blockchain.indexOf(tempRec.getData().substring(1, 9)) > 0) 
			return false;
		
		try {
			for(int i=1; i<20; i++){ 		
				randString = randomAlphaNumeric(8); 								//Create a random string
				data = tempRec.getData() + randString +tempRec.getPreviousHash(); 	//concatenate the block data, the random string (seed) and the previous hash
				MessageDigest MD = MessageDigest.getInstance("SHA-256");
				byte[] bytesHash = MD.digest(data.getBytes("UTF-8")); 				//Hash the concatenated data
				stringOut = ByteArrayToString(bytesHash); 							// convert byte array to a string 
				workNumber = Integer.parseInt(stringOut.substring(0,4),16);			// calculate the work number
				
				if(Blockchain.blockchain.indexOf(tempRec.getData().substring(1, 9)) > 0)		//check again if the temp record is already in the block chain or not 
					return false;
				
				if (workNumber < 10000){
					break;
				}
			}
			Thread.sleep((r.nextInt(9) * 100));
		}catch(Exception ex) {ex.printStackTrace();}
		return true;
	}
	
	//to get the hash number
	public static String getHash(){	
		return stringOut;
	}
	
	//to get the winning seed
	public static String getSeed(){
		return randString;
	}
}

//block chain worker to process the verified block received from the socket
class BlockchainWorker extends Thread { 
    Socket sock; 
    BlockchainWorker (Socket s) {sock = s;} 
    public void run(){
	try{
	    BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
	    String blockData = "";
	    String blockDataIn;
		String blockchainLog ="";
	    while((blockDataIn = in.readLine()) != null){		//read in the information from the socket
			if(blockDataIn.contains("[First Block]")){		//because I sent the block chain string and the json object,
				blockchainLog += blockDataIn;				//this is to make sure the block chain string get updated and
			}												//the incoming data is used correctly.
			else
				blockData += blockDataIn;					//retrieve the json string				
	    }
		
		Gson gson = new Gson();		
		BlockRecord br = gson.fromJson(blockData, BlockRecord.class);		//convert the json string back to Block record type
		Blockchain.BlockchainQueue.add(br);									//add the block record to the block chain
		callBlockLedgerServer();											//to connect to BlockLedgerServer
		Blockchain.blockchain = blockchainLog;								//update the block chain string with the current one
		
	    sock.close(); 
		
	} catch (IOException x){x.printStackTrace();}
    }
	
	//to connect to BlockLedgerServer
	public static void callBlockLedgerServer(){
		Socket Sock1;
		PrintStream toBlockLedgerServer;
		try {
			//send the updated Block chain queue to all the processes (include this one) in json string 
			for(int i=0; i < Blockchain.numProcesses; i++){
				Sock1 = new Socket(Blockchain.serverName, Ports.BlockLedgerServerPortBase + i);
				toBlockLedgerServer = new PrintStream(Sock1.getOutputStream());
				Gson gson = new GsonBuilder().setPrettyPrinting().create();
				toBlockLedgerServer.println(gson.toJson(Blockchain.BlockchainQueue)); 
				toBlockLedgerServer.flush();
				Sock1.close();
			}
		}catch(Exception e){}
	}
}

//block ledger worker to process the updated ledger received from the socket
class BlockLedgerWorker extends Thread { 
    Socket sock;
	
    BlockLedgerWorker (Socket s) {sock = s;} 
    public void run(){
	try{
	    BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
	    String blockData = "";
	    String blockDataIn;
	    while((blockDataIn = in.readLine()) != null){				//read the information from the socket, in this case
			blockData += blockDataIn;								//it is the blockchain ledger		
	    }
		PriorityBlockingQueue<BlockRecord> tempQueue = new PriorityBlockingQueue<>(100, Blockchain.BlockTSComparator);
		Gson gson = new Gson();
		//convert the json string to a linked list of block records
		LinkedList<BlockRecord> temp = gson.fromJson(blockData, new TypeToken<LinkedList<BlockRecord>>(){}.getType()); 
		int n = 0;
		
		BlockRecord tempBlock = null;
		//each item in the temp linked list will be added to the priority queue
		for(BlockRecord item: temp){
			tempQueue.add(item);
		}
		
		gson = new Gson();
		if(Blockchain.PID == 0) {														//if in the process 0, write a json file to disk
			try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
					gson.toJson(Blockchain.BlockchainQueue, writer);
			} catch (IOException e) {
					e.printStackTrace();
			}	
		}
		//set the current block chain queue to the updated one
		Blockchain.BlockchainQueue = tempQueue;
		
		
	} catch (IOException x){x.printStackTrace();}
    }
}

// class to start the block ledger server, to receive the updated ledger from processes
class BlockLedgerServer implements Runnable {
	public void run(){
		int q_len = 6; 
		Socket sock;
		System.out.println("Starting the Block Ledger server input thread using " + Integer.toString(Ports.BlockLedgerServerPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.BlockLedgerServerPort, q_len);		//start a new server
			while (true) {											//listen to and accept the socket request
				sock = servsock.accept();				
				new BlockLedgerWorker (sock).start();				//start a new worker 
			}
		}catch (IOException ioe) {System.out.println(ioe);}			//for any exception
	}
}

// class to start the block chain server, to receive the verfied block from processes
class BlockchainServer implements Runnable {
    public void run(){
		int q_len = 6; 
		Socket sock;
		System.out.println("Starting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);			//start a new server
			while (true) {											//listen to and accept the socket request
			sock = servsock.accept();	
			new BlockchainWorker (sock).start(); 					//start a new worker 
			}
		}catch (IOException ioe) {System.out.println(ioe);}			//for any exception
    }
}
 
public class Blockchain {
	public static String serverName = "localhost";
	static String blockchain = "[First Block]"; 								//to store every block record 
	public static ArrayList<ProcessBlock> processBlock = new ArrayList<>();		//store the processBlock information (pid and public keys)
	public static String sign = "abcd";				//for the block record's signature
	private static KeyPair pair;					//variable for KeyPair
	public static int PID;							//Process number
	public static int numProcesses = 3;				//the number of processes
	
	//to compare the time stamp of each block record for the PriorityBlockingQueue
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
	
	//the final block chain queue with all the block records after the program works through
	static PriorityBlockingQueue<BlockRecord> BlockchainQueue = new PriorityBlockingQueue<>(100, BlockTSComparator);
	//to store the received UVB for later use
	final static PriorityBlockingQueue<BlockRecord> PriorityQueue = new PriorityBlockingQueue<>(100, BlockTSComparator);
	
	//for verifying the signature from the unverified block 
	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sig));
	}	
		
	//for creating a signature for the block record
	public static  byte[] signData(byte[] data, PrivateKey key) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		return (signer.sign());
	}
	
	//generated the key pair (public/private key)
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
	
	//read from the file and then input it in the block record
	public static void input(){
		int iFNAME = 0;
		int iLNAME = 1;
		int iDOB = 2;
		int iSSNUM = 3;
		int iFavorite_show = 4;
		int iSteamingService = 5;
		int iNextShow = 6;
		String FILENAME;		
		
		//depend on the PID, read the corresponding file
		switch(PID){
			case 1: FILENAME = "BlockInput1.txt"; break;
			case 2: FILENAME = "BlockInput2.txt"; break;
			default: FILENAME= "BlockInput0.txt"; break;
		}

		System.out.println("Using input file: " + FILENAME);

		try {
			BufferedReader br = new BufferedReader(new FileReader(FILENAME)); //read the file
			String[] tokens = new String[10];			//to store the individual data from the file
			String InputLineStr;
			String suuid;								//to store the blockID
			UUID idA;
			BlockRecord tempRec;      
			
			BlockRecord dummyBlock = new BlockRecord();			//create first (dummy) block record, 
			suuid = new String(UUID.randomUUID().toString());	//create a uuid for the block ID
			dummyBlock.setBlockID(suuid);
			//set the dummy block record's data corresponding with the input data
			dummyBlock.setFname("First");
			dummyBlock.setLname("Block");
			dummyBlock.setVerificationProcessID("0");
			dummyBlock.setPreviousHash("00000000000000000000");	//initialize the previousHash value
																//Should I let it point to itself?
			Work test = new Work(dummyBlock);				//do some work for the first block 
			if(test.proofWork() == true) {					
				dummyBlock.setHash(test.getHash());			//set the Hash number
				dummyBlock.setRandomSeed(test.getSeed());	//set the winning seed	
			}
			//add the block record to the priority queue
			Blockchain.BlockchainQueue.add(dummyBlock);
			
			while ((InputLineStr = br.readLine()) != null) {		//read line by line
	
				BlockRecord BR = new BlockRecord(); 
				try{Thread.sleep(1001);}catch(InterruptedException e){}
				Date date = new Date();										//generate date for the time stamp
				String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
				String TimeStampString = T1 + "." + PID; 
				BR.setTimeStamp(TimeStampString); 					//set the time received 

				suuid = new String(UUID.randomUUID().toString());	//generate blockID
				BR.setBlockID(suuid);
				tokens = InputLineStr.split(" +"); 					// split the string read from the file and put in an array
				//set the block record's data corresponding with the input data
				BR.setFname(tokens[iFNAME]);
				BR.setLname(tokens[iLNAME]);
				BR.setSSNum(tokens[iSSNUM]);
				BR.setDOB(tokens[iDOB]);
				BR.setfavorite_show(tokens[iFavorite_show]);
				BR.setsteamingService(tokens[iSteamingService]);
				BR.setNextShow(tokens[iNextShow]);
				BR.setCreatorProcess(Integer.toString(Blockchain.PID));
				try {
					BR.setCreatorSigned(signData(sign.getBytes(), pair.getPrivate()));
				} catch (Exception e) {}
				//add the block record to the priority queue
				PriorityQueue.add(BR);
			}
		}catch (IOException e) {e.printStackTrace();}
	}
	
	//multicast the key to all the servers
	public static void KeySend (KeyPair pair){ 
		Socket sock;
		PrintStream toServer;
		try{
			//send the public key to all the servers (include this one) in json string 
			for(int i=0; i< numProcesses; i++){	
				sock = new Socket(serverName, Ports.KeyServerPortBase + i);
				toServer = new PrintStream(sock.getOutputStream());
				byte[] byte_key = pair.getPublic().getEncoded();					//get the public string in byte format
				String publicKey = Base64.getEncoder().encodeToString(byte_key);	//convert the public key to string format
				Gson gson = new GsonBuilder().setPrettyPrinting().create();
				String json = gson.toJson(publicKey);								//convert the string to json
				toServer.println(PID);												//send to the server process ID
				toServer.println(json);												//send to the server the json string
				toServer.flush();
				sock.close();
			}
		}catch (Exception x) {x.printStackTrace ();}
    }

    public void UnverifiedSend (){ 

		Socket UVBsock; 
		BlockRecord tempRec;
		Random r = new Random();
	
		try{
			Blockchain.input();						//read in the file input
			Iterator<BlockRecord> iterator = PriorityQueue.iterator();

			PrintStream toServerOOS = null; 
			
			//Using this method to send the unverified block 
			//Send the Unverified Blocks to each process including this one
			for(int i = 0; i < numProcesses; i++){
				System.out.println("Sending UVBs to process " + i + "...");			
				iterator = PriorityQueue.iterator();
				//when there are still items in the queue, continue to send the data to each server
				while(iterator.hasNext()){					
					UVBsock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
					toServerOOS = new PrintStream(UVBsock.getOutputStream());
					//When I used this, process 2 has a lot data compare to process 0 
					//and process 1 also has a lot more data than process 0
					//so this is to help other process to catch up with process 0
					if( i ==0 )
						Thread.sleep((r.nextInt(9) * 200));
					else if ( i == 1)
						Thread.sleep((r.nextInt(9) * 150));
					else
						Thread.sleep((r.nextInt(9) * 100));
					
					tempRec = iterator.next();
					Gson gson = new GsonBuilder().setPrettyPrinting().create();
					toServerOOS.println(gson.toJson(tempRec)); 		// Send the unverified block in json string
					toServerOOS.flush();
					UVBsock.close();
				} 
			}
	    
			Thread.sleep((r.nextInt(9) * 100));
		
		}catch (Exception x) {}
    }
	
	public static void main(String args[]){
		Blockchain block = new Blockchain();
		block.run(args);
	}
	
	public static void run (String args[]){
		//take in the arguments from the cmd
		if (args.length < 1)	
			PID = 0;
		else
			PID = Integer.parseInt(args[0]);
		
		System.out.println("Linh Do's rudimentary block chain");
		System.out.println("Using processID " + PID + "\n");
			
		pair = new Blockchain().generateKeyPair();						//generate public/private key 	
		new Ports().setPorts(PID);										//calculate the port number base on the process number		
		new Thread(new PublicKeyServer()).start();						//start public key server thread   
		new Thread(new UnverifiedBlockServer(PriorityQueue)).start(); 	//start unverified block server thread
		new Thread(new BlockchainServer()).start();						//start block chain server thread 	
		new Thread(new BlockLedgerServer()).start();					//start block ledger server thread 

		//sleep so other process can catch up
		try{
			Thread.sleep(1000);
		}catch(Exception e){} 
		
		KeySend(pair);							//multicast the public key to other processes
		
		try{
			Thread.sleep(1000);
		}catch(Exception e){} 
		
		new Blockchain().UnverifiedSend();		//start to read the input and send the information to other process
		
		try{
			Thread.sleep(1000);
		}catch(Exception e){}
		
		new Thread(new UnverifiedBlockConsumer(PriorityQueue)).start();		//start processing the information received from other process 
		
		try{Thread.sleep(1000);}catch(Exception e){}
	}		
}