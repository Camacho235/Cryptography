
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

//PseudoRandom version of RSA
public class RSA {
	
	private BigInteger privateKey;
	private BigInteger publicKey;
	private BigInteger n;
	
	public static void main(String args[]) {
		RSA rsaInstance = new RSA(2048);
		rsaInstance.keyGeneration(1028);
		
		BigInteger message = new BigInteger("40123");
		BigInteger ciphertext = rsaInstance.encrypt(message);
		
		System.out.println(message);
		System.out.println(ciphertext);
		System.out.println(rsaInstance.decrypt(ciphertext));
		//System.out.println(rsaInstance.toString());

		
	}
	/**
	 * This is the constructor for RSA
	 * Creates an RSA instance
	 */
	public RSA(int length) {
		
	}
	
	@Override
	public String toString() {
		//Not sure if there is standard for parsing RSA strings, for now print like this
		return this.publicKeyString() + "\n\n" + this.privateKeyString();
		
	}
	
	public String privateKeyString() {
		//Not sure if there is standard for parsing RSA strings, for now print like this
		String result = "----BEGIN RSA PRIVATE KEY-----\n";
		result += privateKey.toString().replaceAll("(.{50})", "$1\n");
		result += "\n----END RSA PRIVATE KEY-----";
		return result;
	}
	
	public String publicKeyString() {
		//Not sure if there is standard for parsing RSA strings, for now print like this
		String result = "----BEGIN RSA PUBLIC KEY-----\n";
		result += publicKey.toString().replaceAll("(.{50})", "$1\n");
		result += "\n----END RSA PUBLIC KEY-----";
		return result;
	}
	
	/**
	 * RSA key generation
	 * @param length specifies the number of bits in the encryption scheme
	 * @return a BigInteger array of length 3 consisting of n, privateExp, publicExp in 
	 */
	public void keyGeneration(int length) {
		BigInteger one = new BigInteger("1");
		SecureRandom rnd = new SecureRandom();
		
		BigInteger p = BigInteger.probablePrime(length, rnd);
		BigInteger q = BigInteger.probablePrime(length, rnd);
		
		BigInteger[] eeaResult;
		
		BigInteger phi = (p.subtract(one)).multiply(q.subtract(one));
		
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
	
	
	public BigInteger encrypt(BigInteger plaintext) {
		return plaintext.modPow(this.publicKey, this.n);
	}
	
	public BigInteger decrypt(BigInteger ciphertext) {
		return ciphertext.modPow(this.privateKey, this.n);
	}
}
