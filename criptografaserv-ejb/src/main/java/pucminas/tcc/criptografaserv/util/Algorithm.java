package pucminas.tcc.criptografaserv.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;

/**
 * Classe abstrata dos algoritmos criptografia
 * @author Lucas Santiago
 *
 */
public abstract class Algorithm implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Metodo que retira os espacos em branco apos a mensagem original.
	 * @param original
	 * @return
	 */
	public static String nullPadString(String original) {
		StringBuffer output = new StringBuffer(original);
		int remain = output.length() % 16;
		if (remain != 0) {
			remain = 16 - remain;
			for (int i = 0; i < remain; i++) {
				output.append((char) 0);
			}
		}
		return output.toString();
	}

	/**
	 * Metodo que transforma a mensagem cifrada de array de bytes em hexadecimal
	 * @param hex
	 * @return
	 */
	public static String byteArrayToHex(byte[] hex) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < hex.length; i++) {
			sb.append(Integer.toString((hex[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return sb.toString();
	}

	/**
	 * Metodo que transforma a mensagem cifrada como hexadecimal no banco de dados e transforma em array de bytes.
	 * @param s
	 * @return
	 */
	public static byte[] hexToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	
	
	/**
	 * Converte um arquivo em um array de bytes.
	 * 
	 * @param stream
	 * @return
	 * @throws IOException
	 * @author Lucas Santiago
	 */
	public static byte[] readFully(InputStream stream) throws IOException {

		byte[] buffer = new byte[8192];
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int bytesRead = stream.read(buffer);
		while(bytesRead != -1) {
			baos.write(buffer, 0, bytesRead);
			bytesRead = stream.read(buffer);
		}
		return baos.toByteArray();
	}

}
