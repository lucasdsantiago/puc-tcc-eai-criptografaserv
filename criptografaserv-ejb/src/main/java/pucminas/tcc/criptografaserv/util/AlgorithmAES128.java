package pucminas.tcc.criptografaserv.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



/**
 * Classe que implementa o Algorotimo Criptografico AES com o tamanho da chave
 * de 128 bits.
 * 
 * @author Lucas Santiago
 * 
 */
public class AlgorithmAES128 extends Algorithm {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static AlgorithmAES128 algorithmAES128Singleton;
	private static byte[] keyPrivate;
	private static KeyGenerator kgen;
	private static SecretKeySpec skeySpec;
	private static Cipher cipher;
	private static String diretorioServidor = System.getProperty("catalina.base");
	private static final int keySize = 128;
	

	private AlgorithmAES128() {
	}

	public static AlgorithmAES128 getInstance()
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		if (algorithmAES128Singleton == null) {
			kgen = KeyGenerator.getInstance("AES");
			kgen.init(keySize);
			
			keyPrivate = getKeyPrivateAES128();
			
			skeySpec = new SecretKeySpec(keyPrivate, "AES");
			cipher = Cipher.getInstance("AES/ECB/NoPadding");
			
			algorithmAES128Singleton = new AlgorithmAES128();
		}
		return algorithmAES128Singleton;
	}

	/**
	 * Metodo que retorna a chave criptografica.
	 * @return
	 */
	public static byte[] getKeyPrivateAES128() {
		byte[] key = "PUCMINASTCCEAILUCASDIASSANTIAGO".getBytes();
		MessageDigest sha = null;
		try {
			sha = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit

		return key;
	}


	/**
	 * Metodo que gera a chave criptografica e grava no disco como arquivo.
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void keyGeneratorInFileAES128() throws NoSuchAlgorithmException, IOException {

			// Generate the secret key specs.
			KeyGenerator kGenerator = KeyGenerator.getInstance("AES");
			kGenerator.init(keySize);
			SecretKey skey = kGenerator.generateKey();
			final byte[] keyPrivateGenerator = skey.getEncoded();

			File file = new File(diretorioServidor + File.separatorChar + "chavecriptografica.sdscryption");

			if(!file.exists()){
				FileOutputStream fos = new FileOutputStream(file);

				fos.write(keyPrivateGenerator);
				fos.close();
				Logger.getLogger(AlgorithmAES128.class.getName()).log(Level.INFO, "Chave criptografica gerada com sucesso!", "");
			}
			else Logger.getLogger(AlgorithmAES128.class.getName()).log(Level.WARNING, "Tentativa de gerar uma nova chave criptografica. Chave existente.", "");
	}

	/**
	 * Metodo de cifra.
	 * @param message
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encryption(Object message) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		byte[] msgEncode = cipher.doFinal(nullPadString(message.toString())
				.getBytes());

		return byteArrayToHex(msgEncode);

	}

	/**
	 * Metodo de decifra.
	 * @param encrypted
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String dencryption(String encrypted) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		byte[] msgEncrypted = hexToByteArray(encrypted);
		byte[] original = cipher.doFinal(msgEncrypted);

		return new String(original).trim();

	}
	
	/**
	 * Metodo que realiza a cifra do arquivo de entrada.
	 * @param fileToEncrypt arquivo de entrada que sera cifrado.
	 * @param encryptedFile arquivo cifrado.
	 * @throws Exception
	 */
	public void encryption(InputStream fileToEncrypt, OutputStream encryptedFile) throws IOException, InvalidKeyException {
        encryptOrDecrypt(Cipher.ENCRYPT_MODE, fileToEncrypt, encryptedFile);
	}

	/**
	 * Metodo que realiza a decifra do arquivo cifrado.
	 * @param encryptedFile arquivo cifrado.
	 * @param decryptedFile arquivo decifrado.
	 * @throws Exception
	 */
	public void dencryption(InputStream encryptedFile, OutputStream decryptedFile) throws IOException, InvalidKeyException {
        encryptOrDecrypt(Cipher.DECRYPT_MODE, encryptedFile, decryptedFile);
	}
	
	/**
	 * Metodo que cifra ou decifra o arquivo de acordo com o modo de operacao.
	 * @param mode mode de operacao cifra ou decifra.
	 * @param is arquivo de entrada
	 * @param os arquivo de saida
	 * @throws Exception
	 */
	private void encryptOrDecrypt(int mode, InputStream is, OutputStream os) throws IOException, InvalidKeyException{
	
        if (mode == Cipher.ENCRYPT_MODE) {
        	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		    CipherInputStream cis = new CipherInputStream(is, cipher);
        	doCopy(cis, os);
			
        } else if (mode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            CipherOutputStream cos = new CipherOutputStream(os, cipher);
            doCopy(is, cos);
        }
	}
	
	/**
	 * Metodo que copia o arquivo de entrada para o arquivo de saida.
	 * @param is
	 * @param os
	 * @throws IOException
	 */
	private void doCopy(InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[1024];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
                os.write(bytes, 0, numBytes);
        }
        os.flush();
        os.close();
        is.close();
	}

}
