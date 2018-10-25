
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;

//PseudoRandom version of RSA
public class RSA {
	
	private BigInteger privateKey;
	private BigInteger publicKey;
	private BigInteger n;
	private BigInteger p;
	private BigInteger q;
	private int length;
	
	public static void main(String args[]) {
		
		//Lets parse the arguments
		if (args.length == 0) {
			RSA rsaInstance = new RSA(2048);
			rsaInstance.keyGeneration();
			BigInteger message = new BigInteger("2452341312313");
			BigInteger ciphertext = rsaInstance.encrypt(message);
			System.out.println(message.toString());
			System.out.println(ciphertext.toString());
			System.out.println(rsaInstance.decrypt(ciphertext));
			System.out.println(rsaInstance.toString());
		}
		else {
			for (int i = 0; i < args.length; i++) {
				if(args[i].equals("-length")) {
					try {
						RSA rsaInstance = new RSA(Integer.parseInt(args[i+1]));
						rsaInstance.keyGeneration();
						System.out.println(rsaInstance.toString());
					}
					catch (NumberFormatException e) {
						System.out.println("Argument for length needs a integer value!");
					}
					catch (ArrayIndexOutOfBoundsException e) {
						System.out.println("Need to enter argument for length!");
					}
					return;
				}
			}
			
		}
		
//		RSA rsaInstance = new RSA(2048);
//		rsaInstance.keyGeneration();
//		
//		BigInteger message = new BigInteger("349082934280");
//		BigInteger ciphertext = rsaInstance.encrypt(message);
//		System.out.println(rsaInstance.toString());
//		System.out.println(message);
//		System.out.println(ciphertext);
//		System.out.println(rsaInstance.decrypt(ciphertext));
		//System.out.println(rsaInstance.toString());

		
	}
	/**
	 * This is the constructor for RSA
	 * Creates an RSA instance
	 */
	public RSA(int length) {
		this.length = length;
	}
	
	@Override
	public String toString() {
		//Not sure if there is standard for parsing RSA strings, for now print like this
		return this.publicKeyString() + "\n\n" + this.privateKeyString();
		
	}
	
	/**
	 * String Representation the RSA private key in base64
	 * @return a string representation of RSA private key
	 */
	public String privateKeyString() {
		//RFC says 
		/*
		  version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
		 */
		//Not sure if there is standard for parsing RSA strings, for now print like this
		String result = "----BEGIN RSA PRIVATE KEY-----\n";
		
		String rsaRFC = "";
		rsaRFC += "1";
		rsaRFC += this.n.toString();
		rsaRFC += this.publicKey.toString();
		rsaRFC += this.privateKey.toString(); //.replaceAll("(.{64})", "$1\n");
		rsaRFC += this.p.toString();
		rsaRFC += this.q.toString();
		
		result += rsaRFC.replaceAll("(.{64})", "$1\n");
		
		result += "\n----END RSA PRIVATE KEY-----";
		return result;
	}
	
	/**
	 * String Representation the RSA public key
	 * @return a string representation of RSA public key
	 */
	public String publicKeyString() {
		//Not sure if there is standard for parsing RSA strings, for now print like this
		String result = "----BEGIN RSA PUBLIC KEY-----\n";
		result += publicKey.toString().replaceAll("(.{64})", "$1\n");
		result += "\n----END RSA PUBLIC KEY-----";
		return result;
	}
	
	/**
	 * RSA key generation
	 * @param length specifies the number of bits in the encryption scheme
	 * @return a BigInteger array of length 3 consisting of n, privateExp, publicExp in 
	 */
	public void keyGeneration() {
		SecureRandom rnd = new SecureRandom();
		
		this.p = BigInteger.probablePrime(this.length/2, rnd);
		this.q = BigInteger.probablePrime(this.length/2, rnd);
		
		BigInteger[] eeaResult;
		
		BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		//Get a public e in range of 1 - phi, st gcd(e, phi) = 1
		
		BigInteger publicExp;
		BigInteger privateExp;
		
		/* We could do this, but it seems standard to use 65537 as the public exponent
		do {
			do {
			    publicExp = new BigInteger(phi.subtract(one).bitLength(), rnd);
			} while (publicExp.compareTo(phi.subtract(one)) >= 0);
		} while (!gcd(publicExp, phi).equals(one));
		*/
		
		//http://www.ietf.org/rfc/rfc4871.txt rsa-sha1 says public exp is 65537
		publicExp = new BigInteger("65537");
		//gcd(phi, e) = s*phi + t*e
		eeaResult = eea(phi, publicExp);
		
		privateExp = eeaResult[2];
				
		this.n = p.multiply(q);
		this.publicKey = publicExp;
		this.privateKey = privateExp;		
	}
	
	/**
	 * The extended Euclidean Algorithm
	 * @param a
	 * @param b
	 * @return a BigInteger array of length 3, giving the result of gcd(a,b) and s, t in gcd(a, b) = s*a + t*b
	 */
	private static BigInteger[] eea(BigInteger a, BigInteger b) {
		
		BigInteger[] result = new BigInteger[3];
		BigInteger q;
		
		int i = 1;
		
		ArrayList<BigInteger> s = new ArrayList<>();
		ArrayList<BigInteger> t = new ArrayList<>();
		ArrayList<BigInteger> r = new ArrayList<>();
		
		//Initialization
		s.add(new BigInteger("1")); //S_0 = 1
		s.add(new BigInteger("0")); //S_1 = 0
		
		t.add(new BigInteger("0")); //t_0 = 0
		t.add(new BigInteger("1")); //t_1 = 1
		
		r.add(a); //r_0 = a
		r.add(b); //r_1 = b
		
		do {
			i += 1;
			r.add(r.get(i-2).mod(r.get(i-1)));
			q = r.get(i - 2).subtract(r.get(i)).divide(r.get(i-1));
			s.add(s.get(i - 2).subtract(q.multiply(s.get(i-1))));
			t.add(t.get(i - 2).subtract(q.multiply(t.get(i-1))));
		} while(!r.get(i).equals(new BigInteger("0")));
		
		result[0] = r.get(i-1);
		result[1] = s.get(i-1);
		result[2] = t.get(i-1);
		
		return result;
	}
	
	/**
	 * Encrypts plain text
	 * @param plaintext the BigInteger representation of the plaintext
	 * @return BigInteger representation of the encrypted plaintext
	 */
	public BigInteger encrypt(BigInteger plaintext) {
		return plaintext.modPow(this.publicKey, this.n);
	}
	
	/**
	 * Encrypts ciphertext
	 * @param plaintext the BigInteger representation of the ciphertext
	 * @return BigInteger representation of the decrypted ciphertext
	 */
	public BigInteger decrypt(BigInteger ciphertext) {
		return ciphertext.modPow(this.privateKey, this.n);
	}
}
