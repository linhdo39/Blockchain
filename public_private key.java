 public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initVerify(key);
    signer.update(data);
    
    return (signer.verify(sig));
  }
  
  public static KeyPair generateKeyPair(long seed) throws Exception {
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rng.setSeed(seed);
    keyGenerator.initialize(1024, rng);
    
    return (keyGenerator.generateKeyPair());
  }
  
  public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initSign(key);
    signer.update(data);
    return (signer.sign());
  }
  
  MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update (CSC435Block.getBytes());
    byte byteData[] = md.digest();
    
    // CDE: Convert the byte[] to hex format. THIS IS NOT VERFIED CODE:
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < byteData.length; i++) {
      sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
    }
    
    String SHA256String = sb.toString();

    KeyPair keyPair = generateKeyPair(999); // Use a random seed in real life

    byte[] digitalSignature = signData(SHA256String.getBytes(), keyPair.getPrivate());

    boolean verified = verifySig(SHA256String.getBytes(), keyPair.getPublic(), digitalSignature);
    System.out.println("Has the signature been verified: " + verified + "\n");
    
    System.out.println("Hexidecimal byte[] Representation of Original SHA256 Hash: " + SHA256String + "\n");
    
    /* Later you'll add this SHA256String to the header for the block. Here we turn the
       byte[] signature into a string so that it can be placed into
       the block as a string, but also show how to return the string to a
       byte[], which you'll need if you want to use it later.
       Thanks Hugh Thomas for the fix! */
    
    SignedSHA256 = Base64.getEncoder().encodeToString(digitalSignature);
    System.out.println("The signed SHA-256 string: " + SignedSHA256 + "\n");
    byte[] testSignature = Base64.getDecoder().decode(SignedSHA256);
    System.out.println("Testing restore of signature: " + Arrays.equals(testSignature, digitalSignature));
    
    verified = verifySig(SHA256String.getBytes(), keyPair.getPublic(), testSignature);
    System.out.println("Has the restored signature been verified: " + verified + "\n");

    /* In this section we show that the public key can be converted into a string suitable
       for marshaling in XML or JSON to a remote machine, but then converted back into usable public
       key. Then, just for added assurance, we show that if we alter the string, we can
       convert it back to a workable public key in the right format, but it fails our
       verification test. */
    
    byte[] bytePubkey = keyPair.getPublic().getEncoded();
    System.out.println("Key in Byte[] form: " + bytePubkey);
    
    String stringKey = Base64.getEncoder().encodeToString(bytePubkey);
    System.out.println("Key in String form: " + stringKey);
    
    String stringKeyBad = stringKey.substring(0,50) + "M" + stringKey.substring(51);
    System.out.println("\nBad key in String form: " + stringKeyBad);

    // Convert the string to a byte[]:
    
    byte[] bytePubkey2  = Base64.getDecoder().decode(stringKey);
    System.out.println("Key in Byte[] form again: " + bytePubkey2);
    
    X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bytePubkey2);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey RestoredKey = keyFactory.generatePublic(pubSpec);
    
    verified = verifySig(SHA256String.getBytes(), keyPair.getPublic(), testSignature);
    System.out.println("Has the signature been verified: " + verified + "\n");
    
    verified = verifySig(SHA256String.getBytes(), RestoredKey, testSignature);
    System.out.println("Has the CONVERTED-FROM-STRING signature been verified: " + verified + "\n")
	
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
	
	public static LinkedList<BlockRecord> readLedgerJson (String input) {
		LinkedList<BlockRecord> blockRecordIn = null;
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